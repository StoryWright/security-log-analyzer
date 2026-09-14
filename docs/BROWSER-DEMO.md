# Browser demo

Live URL: https://storywright.github.io/security-log-analyzer/

Load a sample or paste authentication logs, change the detection window, inspect evidence, and download reports.

## Build and run locally

Use Node.js 22 or newer. Run `node --test`, then `node scripts/build-site.mjs`. Serve `_site/` with any local static HTTP server (for example `python -m http.server 8000 --directory _site`) and open its localhost URL. ES modules and fixture loading require HTTP; opening index.html as a file is not supported.

`site/` contains the interface. The build copies the current `src/analyzer.js` into `_site/engine.js`, replacing Node-specific imports with the small browser compatibility adapter in `site/platform.js`. There is no separate implementation of the detection or support workflow rules. The CLI source is unchanged.

The IP adapter accepts strict dotted IPv4 and URL-valid IPv6 addresses. The browser limits pasted or selected input to 1 MiB and 10,000 valid events and supports JSONL, legacy, and dated SSH records. Sample loading replaces the editor; input is analyzed locally and is not uploaded. No analytics or browser storage is used by the interface.

The Pages workflow runs the engine and browser interaction tests, builds `_site/`, and deploys only that generated directory using GitHub Pages. The existing project-check workflow continues to test the CLI on Windows and Linux. GitHub remains the website host and processes ordinary website requests.

## Validation scope

Browser-engine tests compare the generated demo engine with the Node engine on the fixtures and changed settings. Browser interaction checks cover controls, exports, empty/error states, and narrow screens. These checks establish the demo's behavior; live Active Directory, Wazuh, and Sysmon deployments are separate work.

## Run the browser checks

After `npm ci`, run `npx playwright install chromium` (on Linux use `--with-deps` if needed), then `npm run test:browser`. The checks start a temporary local HTTP server and isolated headless Chromium, exercise the interface, and close both afterward. They do not use your personal browser profile. Playwright is a development-only dependency; the CLI and published demo need no installed third-party runtime libraries.

Set `DEMO_URL` to test a deployed copy instead. Set `CAPTURE_DIR` to save desktop/mobile screenshots and the check results. `BROWSER_EXECUTABLE` can select an installed compatible Chromium executable. The Pages workflow uses the pinned Playwright browser build. Deployment happens only if these checks pass.
