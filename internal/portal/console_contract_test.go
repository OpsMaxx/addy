package portal

import (
	"fmt"
	"io/fs"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The consoles are HTML files, scripts and one stylesheet with no build step
// between them, so nothing checks that they agree. Every defect this file
// guards was shipped and reported by a user: a control whose listener was never
// attached looks exactly like a control that works, and the page has no way to
// complain.
//
// These tests read the files as TEXT. That is the point — the disagreement they
// catch is a disagreement between files, which is invisible to any test that
// exercises one of them.
//
// EVERY PAGE IS FOUND RATHER THAN LISTED. There are two consoles today —
// /console is yours, /console/relay is the relay's — and they share
// console-kit.js, but a list written here would be a list somebody forgets to
// add the next page to. That is not a hypothetical: the stylesheet defect at
// the bottom of this file WAS fixed, scoped to one page, and the page nobody
// thought of kept the bug. So the pages come from the embedded files, and each
// page's script is its own plus whatever that imports.

func readWeb(t *testing.T, name string) string {
	t.Helper()
	b, err := assets.ReadFile("web/" + name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(b)
}

// aPage is one HTML file and every line of script that runs on it. They are
// one program once the browser has loaded them.
type aPage struct {
	page    string
	scripts string
	// Which files those were, so a failure names something a reader can open.
	from []string
}

// consoles finds every page the portal serves that drives itself with `$`.
// A page whose script never reaches for an id — the front page reads one
// element and deliberately does nothing else — has nothing here to disagree
// with.
func consoles(t *testing.T) []aPage {
	t.Helper()
	names, err := fs.Glob(assets, "web/*.html")
	if err != nil {
		t.Fatalf("globbing the pages: %v", err)
	}
	sort.Strings(names)

	var out []aPage
	for _, name := range names {
		html := readWeb(t, path.Base(name))
		entry := pageScript.FindStringSubmatch(html)
		if entry == nil {
			continue
		}
		p := aPage{page: path.Base(name)}
		seen := map[string]bool{}
		var pull func(string)
		pull = func(js string) {
			if seen[js] {
				return
			}
			seen[js] = true
			body := readWeb(t, js)
			p.scripts += body + "\n"
			p.from = append(p.from, js)
			// Transitively: the session rules live in a shared module, and an
			// id that moved there must not stop being checked.
			for _, m := range localImport.FindAllStringSubmatch(body, -1) {
				pull(m[1])
			}
		}
		pull(entry[1])
		if !strings.Contains(p.scripts, "$(") {
			continue
		}
		out = append(out, p)
	}
	if len(out) < 3 {
		t.Fatalf("the parser is wrong, not the code: found %d pages that drive themselves with $()", len(out))
	}
	return out
}

var (
	// An element id as the page declares it.
	htmlID = regexp.MustCompile(`id="([A-Za-z0-9_-]+)"`)
	// An id as a script asks for it. `$` is a script's only way to reach the
	// page, so this is the complete list of what it expects to find.
	scriptID = regexp.MustCompile(`\$\('([A-Za-z0-9_-]+)'\)`)
	// One whole tag, so `id` and `hidden` can be read off the same element
	// rather than off the same file.
	htmlTag = regexp.MustCompile(`<[a-zA-Z][^>]*>`)
	// A bare `hidden` attribute, not `data-hidden` and not `hidden="x"` — the
	// pages only ever write the bare form, which is the one the browser's
	// user-agent stylesheet acts on.
	bareHidden = regexp.MustCompile(`\shidden(\s|/?>)`)
	// An element held under a local name instead of its `$()` call, in either
	// of the two forms the scripts use: `const p = $('problem')`, and
	// `{ out: $('invite') }` where a helper is handed the elements it drives.
	// Resolving one hop of that is the difference between these tests being
	// true and them needing a standing exemption for every element a helper
	// touches.
	aliased = regexp.MustCompile(`(?:const\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*[:=]\s*\$\('([A-Za-z0-9_-]+)'\)`)
	// The script a page loads, and the modules that script pulls in.
	pageScript  = regexp.MustCompile(`<script[^>]*\ssrc="/assets/([A-Za-z0-9_.-]+\.js)"`)
	localImport = regexp.MustCompile(`from\s+'\./([A-Za-z0-9_.-]+\.js)'`)
)

func aliases(script string) map[string]string {
	out := map[string]string{}
	for _, m := range aliased.FindAllStringSubmatch(script, -1) {
		out[m[1]] = m[2]
	}
	return out
}

func TestEveryIdTheScriptReachesForExistsInThePage(t *testing.T) {
	// A typo'd id is a control that silently does nothing: `$('signot')`
	// returns null, the listener is never attached, and the button renders
	// perfectly. Nothing in the browser console says so unless the null is
	// dereferenced, and half of these are only dereferenced on a code path
	// most sessions never take.
	ids, lookups := 0, 0
	for _, c := range consoles(t) {
		page := readWeb(t, c.page)

		declared := map[string]bool{}
		for _, m := range htmlID.FindAllStringSubmatch(page, -1) {
			declared[m[1]] = true
		}
		ids += len(declared)

		wanted := map[string]bool{}
		for _, m := range scriptID.FindAllStringSubmatch(c.scripts, -1) {
			wanted[m[1]] = true
		}
		lookups += len(wanted)

		for id := range wanted {
			if !declared[id] {
				t.Errorf("%s reaches for #%s and %s has no such element.\n"+
					"$() returns null there, so whatever that line was for does not happen.",
					strings.Join(c.from, " or "), id, c.page)
			}
		}
	}
	// Counted across the pages rather than within one, because a page that
	// declares few ids is a small page and not a broken parser.
	if ids < 30 || lookups < 30 {
		t.Fatalf("the parser is wrong, not the code: %d ids and %d $() lookups in total", ids, lookups)
	}
}

func TestEveryElementThatStartsHiddenCanBeUnhidden(t *testing.T) {
	// Everything role-specific starts hidden, because a page loaded without a
	// session must not flash a console before it knows there is nobody signed
	// in. That makes the unhide the only thing keeping each section alive: an
	// id with no code path that clears its `hidden` is dead UI that no reader
	// of either file can tell from working UI.
	hiddens, assignments := 0, 0
	for _, c := range consoles(t) {
		page := readWeb(t, c.page)

		startsHidden := map[string]bool{}
		declared := map[string]bool{}
		for _, tag := range htmlTag.FindAllString(page, -1) {
			id := htmlID.FindStringSubmatch(tag)
			if id == nil {
				continue
			}
			declared[id[1]] = true
			if bareHidden.MatchString(tag) {
				startsHidden[id[1]] = true
			}
		}
		hiddens += len(startsHidden)

		alias := aliases(c.scripts)
		canBeShown := map[string]bool{}
		byName := false
		for _, m := range regexp.MustCompile(
			`(?m)(?:\$\('([A-Za-z0-9_-]+)'\)|\$\(([A-Za-z_$][A-Za-z0-9_$]*)\)|([A-Za-z_$][A-Za-z0-9_$]*))\.hidden\s*=\s*(.+)$`,
		).FindAllStringSubmatch(c.scripts, -1) {
			// `= true` only ever hides. Anything else — `false`, or a condition
			// — is a path on which the element can appear.
			clears := strings.TrimSpace(m[4]) != "true"
			switch {
			case m[1] != "":
				assignments++
				if clears {
					canBeShown[m[1]] = true
				}
			case m[2] != "":
				// `$(id).hidden = …`, a loop showing one of a set of sections
				// and hiding the rest. The set is a literal list of ids beside
				// it; see below.
				assignments++
				byName = byName || clears
			case alias[m[3]] != "": // a name the script never took from $() is not an element
				assignments++
				if clears {
					canBeShown[alias[m[3]]] = true
				}
			}
		}

		// Only reached when such a loop exists, and only for ids this page
		// actually declares — so on a page without one it grants nothing, and
		// on a page with one it grants exactly the ids written down beside it.
		if byName {
			for _, arr := range regexp.MustCompile(`\[\s*'[^']+'(?:\s*,\s*'[^']+')*\s*\]`).FindAllString(c.scripts, -1) {
				for _, lit := range regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(arr, -1) {
					if declared[lit[1]] {
						canBeShown[lit[1]] = true
					}
				}
			}
		}

		for id := range startsHidden {
			if !canBeShown[id] {
				t.Errorf("#%s starts hidden in %s and no line in %s ever clears it.\n"+
					"It is either dead markup or a control somebody will report as missing.",
					id, c.page, strings.Join(c.from, " or "))
			}
		}
	}
	if hiddens < 20 || assignments < 15 {
		t.Fatalf("the parser is wrong, not the code: %d elements start hidden and %d `.hidden =` assignments matched",
			hiddens, assignments)
	}
}

func TestEveryButtonHasAListener(t *testing.T) {
	// THE DEFECT THAT WAS REPORTED. A button whose listener is never attached
	// is indistinguishable from one that works until it is clicked, and the
	// code that attaches the listener is usually the same code that decided
	// whether to show the button at all — so the two go wrong together.
	//
	// A button may be wired in one of exactly two ways, and both are named
	// here so that a third way has to be added in a diff a reviewer sees:
	//
	//	$('id').addEventListener(…)          — wired where it is found
	//	helper({ button: $('id'), … })       — handed to a helper that wires it
	//
	// The second form is only accepted from a page whose script is separately
	// shown to attach a listener to the element it is handed — otherwise
	// "passed to a helper" would be a way to pass this test by doing nothing.
	buttons := 0
	for _, c := range consoles(t) {
		page := readWeb(t, c.page)
		handled := regexp.MustCompile(`button\.addEventListener`).MatchString(c.scripts)

		for _, tag := range regexp.MustCompile(`<button\b[^>]*>`).FindAllString(page, -1) {
			buttons++
			id := htmlID.FindStringSubmatch(tag)
			if id == nil {
				// Without an id the script cannot reach it, so this is the
				// same defect one step earlier rather than a different rule.
				t.Errorf("a <button> in %s has no id, so nothing can reach it: %s", c.page, tag)
				continue
			}
			// Anchored on the `$()` call rather than searched loosely, so a
			// listener attached to some other element does not count as this
			// button's.
			lookup := regexp.QuoteMeta(`$('` + id[1] + `')`)
			wired := regexp.MustCompile(lookup+`\.addEventListener`).MatchString(c.scripts) ||
				(handled && regexp.MustCompile(`button:\s*`+lookup).MatchString(c.scripts))
			if !wired {
				t.Errorf("<button id=%q> in %s is never wired in %s.\n"+
					"It renders, it looks live, and clicking it does nothing.",
					id[1], c.page, strings.Join(c.from, " or "))
			}
		}
	}
	if buttons < 4 {
		t.Fatalf("the parser is wrong, not the code: found %d <button> tags across every page", buttons)
	}
}

// A CSS rule, as the stylesheet declares it.
type cssRule struct{ selector, body string }

// parseCSS splits a stylesheet into flat rules. Comments go first: this file's
// own comment quotes `[hidden] { display: none }` while explaining the bug, and
// a parser that reads its own documentation as code would pass on a file that
// had lost the rule entirely.
func parseCSS(src string) []cssRule {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	var out []cssRule
	for _, chunk := range strings.Split(src, "}") {
		open := strings.Index(chunk, "{")
		if open < 0 {
			continue
		}
		out = append(out, cssRule{
			selector: strings.TrimSpace(chunk[:open]),
			body:     chunk[open+1:],
		})
	}
	return out
}

func TestHiddenBeatsEveryDisplayRuleOnEveryPage(t *testing.T) {
	// `[hidden] { display: none }` is a USER-AGENT rule, so any author rule
	// setting `display` outranks it. This file sets `display` on `.button`,
	// `.row`, `.token` and `.chip` — most of what the console shows and hides
	// — so without a rule of its own, every element the script hid went on
	// rendering: a Sign out button for somebody who is not signed in, and a
	// Create an invite button for a member of a relay that does not hand them
	// out, which did nothing when clicked.
	//
	// It was fixed once before, scoped to `main.paste`. The console is
	// `main.wrap`, so it kept the bug. Scoped to a page, this rule is a trap
	// for the next page, which is why the scoping is asserted and not just the
	// rule.
	rules := parseCSS(readWeb(t, "portal.css"))
	if len(rules) < 20 {
		t.Fatalf("the parser is wrong, not the code: found %d rules in portal.css", len(rules))
	}

	display := regexp.MustCompile(`(?i)\bdisplay\s*:[^;}]*`)
	displays, found := 0, false
	for _, r := range rules {
		decl := display.FindString(r.body)
		if decl == "" {
			continue
		}
		displays++
		bang := strings.Contains(strings.ToLower(decl), "!important")

		if r.selector == "[hidden]" {
			found = true
			if !strings.Contains(strings.ToLower(decl), "none") || !bang {
				t.Errorf("`[hidden]` declares %q.\n"+
					"It has to be `display: none !important` or an author `display` rule outranks it.", strings.TrimSpace(decl))
			}
			continue
		}

		// Anything else scoped to `[hidden]` is the old, page-scoped fix
		// coming back. Reported on its own, because it is a different mistake
		// from the one below and the advice for it is different.
		if strings.Contains(r.selector, "[hidden]") {
			t.Errorf("`%s` scopes the hidden rule to one page.\n"+
				"Every page that is not that one keeps the bug; the rule belongs on bare `[hidden]`.", r.selector)
			continue
		}
		// `!important` beats `!important` on specificity, so this is the one
		// way another rule can still win.
		if bang {
			t.Errorf("`%s` declares %q, which can outrank `[hidden] { display: none !important }`.",
				r.selector, strings.TrimSpace(decl))
		}
	}
	if displays < 5 {
		t.Fatalf("the parser is wrong, not the code: matched %d `display:` declarations", displays)
	}
	if !found {
		t.Error("portal.css has no unscoped `[hidden] { display: none !important }`.\n" +
			"Without it every element the scripts hide goes on rendering.")
	}
}

func TestTheLeadCardFollowsTheCountBothWays(t *testing.T) {
	// The card was decided once at load and its losing half REMOVED. Deleting
	// your only sync group then left no invite button anywhere, under an empty
	// state saying "create an invite above"; and a device registering from
	// OpsMaxx while the tab sat in the background left it offering a first
	// device to somebody who had one. Both halves have to survive in the page
	// and be repainted whenever the count is read again.
	js := readWeb(t, "console.js")
	for _, id := range []string{"mint-mine-row", "pair-steps", "operator-made"} {
		if strings.Contains(js, `$('`+id+`').remove()`) {
			t.Errorf("console.js removes #%s; a later load cannot bring it back", id)
		}
		if !regexp.MustCompile(`\$\('` + id + `'\)\.hidden = !?first`).MatchString(js) {
			t.Errorf("console.js does not paint #%s from the count", id)
		}
	}
	if !strings.Contains(js, "paintLead(await loadMine())") {
		t.Error("deleting a sync group re-reads the count without repainting the card drawn from it")
	}
	for _, ev := range []string{"'focus'", "'visibilitychange'"} {
		if !strings.Contains(js, "addEventListener("+ev) {
			t.Errorf("console.js does not re-read on %s; a device registered in OpsMaxx is not noticed", ev)
		}
	}
}

func TestThePasswordIsAskedForBeforeTheMessageIsUsedUp(t *testing.T) {
	// The page cannot know a message has a password until it holds the sealed
	// blob, and fetching that is the POST that burns a one-time message. The
	// field used to appear only after decryption failed — after the only
	// chance to type into it.
	page := readWeb(t, "paste.html")
	row := regexp.MustCompile(`<div[^>]*id="password-row"[^>]*>`).FindString(page)
	if row == "" {
		t.Fatal("paste.html has no #password-row")
	}
	if bareHidden.MatchString(row) {
		t.Errorf("#password-row starts hidden: %s", row)
	}
	if strings.Index(page, `id="password"`) > strings.Index(page, `id="reveal"`) {
		t.Error("the password field comes after the button that burns the message")
	}
	if strings.Contains(readWeb(t, "paste.js"), "$('password-row').hidden") {
		t.Error("paste.js toggles #password-row; it has to be there before the burn, not after")
	}
}

func TestTheCopyUsesTheNamingContract(t *testing.T) {
	// "Sync group" is the server's grouping, a roster entry is not a device,
	// and the app's page is "Sync & devices" with one pairing code. Each
	// phrase below shipped saying otherwise.
	for _, c := range []struct{ file, phrase, why string }{
		{"console.html", "one per invite", "the store refuses a second sync group to anybody who has one"},
		{"console.html", "server can count", "the relay cannot count devices"},
		{"console.html", "Type the code into the new machine", "name the app's button: Type a code from another device"},
		{"relay.html", "every device on it", "the relay lists sync groups, not devices"},
		{"relay.html", "a device count", "it is a roster-entry count"},
		{"relay.html", "No accounts yet", "they are sync groups"},
		{"relay.js", "existing account", "they are sync groups"},
		{"relay.js", "Delete account", "they are sync groups"},
		{"relay.js", "|| '—'", "a dash reads as 'no email' as easily as 'nobody'"},
		{"index.html", "That creates your account", "it sets up a first device and a sync group"},
		{"index.html", "needs an invite from whoever runs", "signing in gets you your own first-device invite"},
		{"console-kit.js", "this relay was restarted, or you were signed in for more than eight hours. Sign in again to carry on.'", "a blocked member is told the relay restarted"},
	} {
		if strings.Contains(readWeb(t, c.file), c.phrase) {
			t.Errorf("%s still says %q: %s", c.file, c.phrase, c.why)
		}
	}
	for _, c := range []struct{ file, phrase string }{
		{"console.html", "Sync &amp; devices"},
		{"console.html", "Show a code on this device"},
		{"console.html", "I already use OpsMaxx on another machine"},
		{"console.html", "Type a code from another device"},
		{"console.html", "pairing code"},
		{"index.html", `href="/console"`},
		{"console-kit.js", "no longer lets this account sign in"},
		{"relay.html", "belongs to no sign-in"},
		{"console.html", `id="operator-made"`},
	} {
		if !strings.Contains(readWeb(t, c.file), c.phrase) {
			t.Errorf("%s no longer says %q", c.file, c.phrase)
		}
	}
}

// contrast is the WCAG 2 ratio between two #rrggbb colours.
func contrast(t *testing.T, a, b string) float64 {
	t.Helper()
	lum := func(hex string) float64 {
		var rgb [3]float64
		for i := range rgb {
			var v int
			if _, err := fmt.Sscanf(hex[1+2*i:3+2*i], "%02x", &v); err != nil {
				t.Fatalf("%q is not #rrggbb: %v", hex, err)
			}
			c := float64(v) / 255
			if c <= 0.04045 {
				rgb[i] = c / 12.92
			} else {
				rgb[i] = math.Pow((c+0.055)/1.055, 2.4)
			}
		}
		return 0.2126*rgb[0] + 0.7152*rgb[1] + 0.0722*rgb[2]
	}
	x, y := lum(a), lum(b)
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

func TestEveryThemeClearsAAWhereItWasMeasuredFailing(t *testing.T) {
	// White on the dark theme's danger red was the Delete and Block hover at
	// 3.35:1, and the light theme's faint text — table headers, stat labels —
	// was 4.29:1 on the page. Both are text, so both need 4.5:1, in every one
	// of the three places a theme is declared.
	token := regexp.MustCompile(`(--[a-z-]+):\s*(#[0-9a-fA-F]{6})\b`)
	themes := map[string]map[string]string{}
	for _, r := range parseCSS(readWeb(t, "portal.css")) {
		if !strings.HasPrefix(r.selector, ":root") && !strings.HasPrefix(r.selector, "@media (prefers-color-scheme") {
			continue
		}
		vars := map[string]string{}
		for _, m := range token.FindAllStringSubmatch(r.body, -1) {
			vars[m[1]] = m[2]
		}
		themes[r.selector] = vars
	}
	if len(themes) != 3 {
		t.Fatalf("the parser is wrong, not the code: found %d theme blocks, want 3", len(themes))
	}
	pairs := [][2]string{
		{"--danger-ink", "--danger"},
		{"--text-faint", "--bg-app"},
		{"--text-faint", "--bg-card"},
		{"--text-faint", "--bg-hover"},
		{"--danger", "--bg-elevated"},
	}
	for sel, vars := range themes {
		for _, p := range pairs {
			fg, bg := vars[p[0]], vars[p[1]]
			if fg == "" || bg == "" {
				t.Errorf("%s does not declare %s and %s, so it inherits a pair measured for another theme", sel, p[0], p[1])
				continue
			}
			if r := contrast(t, fg, bg); r < 4.5 {
				t.Errorf("%s: %s %s on %s %s is %.2f:1, under 4.5:1", sel, p[0], fg, p[1], bg, r)
			}
		}
	}
}
