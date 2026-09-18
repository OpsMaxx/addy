// Package services is the five service wizards.
//
// Each one is an embedded compose fragment plus a schema saying what has to be
// true before anything is written. The order is the design: EVERY PREREQUISITE
// IS CHECKED BEFORE THE FIRST BYTE HITS DISK. A wizard that writes half a
// deployment and then discovers the port is taken leaves an operator with a
// broken box and a half-finished config they did not author and cannot read.
//
// THE SERVICES ARE OFF BY DEFAULT AND EACH ONE COSTS SOMETHING. addy's pitch
// is a box that holds nothing worth attacking; every service here weakens that,
// and the wizard says how at the point of the decision rather than in a
// document nobody opens. A relay that also runs Vaultwarden is a relay whose
// compromise is a password database, and saying so is not pessimism -- it is
// the information the operator needs in order to decide that they want it
// anyway, which is a perfectly good answer.
package services

import (
	"embed"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed templates
var templates embed.FS

// FieldKind is what a wizard asks for.
type FieldKind string

const (
	FieldText   FieldKind = "text"
	FieldSecret FieldKind = "secret"
	FieldDomain FieldKind = "domain"
	FieldBool   FieldKind = "bool"
	FieldChoice FieldKind = "choice"
)

// Field is one question.
type Field struct {
	Key      string
	Label    string
	Kind     FieldKind
	Required bool
	Default  string
	Choices  []string
	// Help is shown beside the field. Used for the things an operator cannot
	// be expected to know, not to restate the label.
	Help string
}

// Prereq is something that must be true before the service is written.
type Prereq struct {
	// Name is what the operator sees in the report.
	Name string
	// Check returns nil when satisfied, or the reason it is not -- phrased as
	// something to DO, because a preflight that says "port 443 unavailable" and
	// stops has told the operator what they already suspected.
	Check func(cfg Config) error
	// Fatal marks a prerequisite that refuses rather than warns. A warning
	// that reads like an error teaches people to ignore errors.
	Fatal bool
}

// Service is one wizard.
type Service struct {
	ID   string
	Name string
	// Summary is one line.
	Summary string
	// Cost is what running it gives up, stated at the switch.
	//
	// Required, not optional, and every service here has a non-empty one. A
	// service with nothing to declare has not been thought about.
	Cost    string
	Fields  []Field
	Prereqs []Prereq
	// Template names the file under templates/ that is rendered into the
	// deployment directory.
	Template string
	// Ports the service needs on the host, for the collision check that runs
	// for every service without each one writing its own.
	Ports []int
}

// Config is the answers, plus the instance's own facts.
type Config struct {
	// Values are the wizard's fields by key.
	Values map[string]string
	// Domain is the instance's own hostname, which several services derive
	// their own names from.
	Domain string
	// DeployDir is where compose files live.
	DeployDir string
	// DockerHost overrides the socket, for a proxy.
	DockerHost string
}

func (c Config) value(key string) string { return strings.TrimSpace(c.Values[key]) }

// All returns every wizard, in a stable order.
func All() []Service {
	out := []Service{frp(), headscale(), wireguard(), openvpn(), vaultwarden()}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Find returns one wizard by id.
func Find(id string) (Service, error) {
	for _, s := range All() {
		if s.ID == id {
			return s, nil
		}
	}
	return Service{}, fmt.Errorf("no such service %q; run `addy service list`", id)
}

// CheckResult is one prerequisite's outcome.
type CheckResult struct {
	Name  string
	OK    bool
	Fatal bool
	Why   string
}

// CheckAnswers runs only the prerequisites about the ANSWERS, not about the
// box.
//
// The split is worth having beyond testing. "Is this configuration coherent"
// and "can this machine run it" are different questions asked at different
// moments: a portal showing a form wants the first on every keystroke and the
// second once, and an operator writing a deployment to review before applying
// it does not care that port 8080 is busy on the machine they happen to be
// sitting at.
//
// `Render` still enforces BOTH. Nothing reaches disk on a box that cannot run
// what is being written.
func CheckAnswers(s Service, cfg Config) []CheckResult {
	out := make([]CheckResult, 0, len(s.Prereqs))
	for _, p := range s.Prereqs {
		err := p.Check(cfg)
		out = append(out, CheckResult{
			Name:  p.Name,
			OK:    err == nil,
			Fatal: p.Fatal,
			Why:   errText(err),
		})
	}
	return out
}

// Preview renders what would be written, WITHOUT writing it and without asking
// anything about this machine.
//
// An operator handed a compose file they have not read is an operator running
// something they did not author. This is how they read it first.
func Preview(s Service, cfg Config) (string, error) {
	if Blocking(CheckAnswers(s, cfg)) {
		return "", errors.New("the answers are not complete; run `addy service check` for what is missing")
	}
	body, err := templates.ReadFile(filepath.Join("templates", s.Template))
	if err != nil {
		return "", fmt.Errorf("reading the template for %s: %w", s.ID, err)
	}
	return expand(string(body), cfg), nil
}

// Check runs every prerequisite and returns all of them.
//
// ALL of them, not the first failure. An operator fixing a box wants the whole
// list in one pass: a preflight that stops at the first problem turns a
// ten-minute job into four rounds of run-fix-run, and the fourth round is where
// people give up and disable the checks.
func Check(s Service, cfg Config) []CheckResult {
	out := make([]CheckResult, 0, len(s.Prereqs)+len(s.Ports)+1)

	out = append(out, dockerCheck(cfg))
	for _, port := range s.Ports {
		out = append(out, portCheck(port))
	}
	return append(out, CheckAnswers(s, cfg)...)
}

// Blocking reports whether any fatal check failed.
func Blocking(results []CheckResult) bool {
	for _, r := range results {
		if !r.OK && r.Fatal {
			return true
		}
	}
	return false
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func dockerCheck(cfg Config) CheckResult {
	args := []string{"version", "--format", "{{.Server.Version}}"}
	cmd := exec.Command("docker", args...)
	if cfg.DockerHost != "" {
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+cfg.DockerHost)
	}
	if err := cmd.Run(); err != nil {
		return CheckResult{
			Name:  "Docker is reachable",
			Fatal: true,
			Why: "Docker did not answer. Install it, start it, and make sure this user can " +
				"reach the socket -- `docker version` from this shell is the same question.",
		}
	}
	return CheckResult{Name: "Docker is reachable", OK: true, Fatal: true}
}

// portCheck asks the only question that matters: can this box bind it.
//
// Not "is something listening", which is a different question with a different
// answer inside a container, and not a scan of `docker ps`, which misses
// anything not run by Docker.
func portCheck(port int) CheckResult {
	name := fmt.Sprintf("Port %d is free", port)
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return CheckResult{
			Name:  name,
			Fatal: true,
			Why: fmt.Sprintf("Something already has %d. `ss -lptn 'sport = :%d'` names it. "+
				"addy itself holds 80 and 443 deliberately -- it is the only thing bound to them, "+
				"and every service here reaches the world through it rather than beside it.", port, port),
		}
	}
	ln.Close()
	return CheckResult{Name: name, OK: true, Fatal: true}
}

// requireValue builds a prerequisite that a field was answered.
func requireValue(key, name, why string) Prereq {
	return Prereq{
		Name:  name,
		Fatal: true,
		Check: func(cfg Config) error {
			if cfg.value(key) == "" {
				return errors.New(why)
			}
			return nil
		},
	}
}

// Render writes the deployment, AFTER every fatal check has passed.
//
// Returns the paths written so the CLI can list them: an operator who is handed
// a working service and no idea what changed on their box has been given a
// black box, and the next thing they do is distrust it.
func Render(s Service, cfg Config) ([]string, error) {
	results := Check(s, cfg)
	if Blocking(results) {
		return nil, errors.New("prerequisites are not met; nothing was written")
	}

	body, err := templates.ReadFile(filepath.Join("templates", s.Template))
	if err != nil {
		return nil, fmt.Errorf("reading the template for %s: %w", s.ID, err)
	}

	dir := filepath.Join(cfg.DeployDir, "services")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}

	rendered := expand(string(body), cfg)
	path := filepath.Join(dir, s.ID+".yml")

	// Written to a scratch name and renamed, like every other durable write in
	// this project. A compose file half-written by an interrupted process is
	// one `docker compose up` away from a partial deployment.
	tmp := path + ".part"
	if err := os.WriteFile(tmp, []byte(rendered), 0o640); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return nil, err
	}
	return []string{path}, nil
}

// expand substitutes ${KEY} from the answers and the instance's facts.
//
// Deliberately not text/template. The output is YAML that an operator reads and
// edits; a template language in it means a file that does not mean what it
// says, and the first time somebody pastes a value containing `{{` the error
// comes from a package they did not know was involved.
func expand(body string, cfg Config) string {
	repl := make([]string, 0, len(cfg.Values)*2+4)
	for k, v := range cfg.Values {
		repl = append(repl, "${"+k+"}", v)
	}
	repl = append(repl, "${DOMAIN}", cfg.Domain)
	repl = append(repl, "${GENERATED_AT}", time.Now().UTC().Format(time.RFC3339))
	return strings.NewReplacer(repl...).Replace(body)
}
