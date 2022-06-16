# PentagridScanController
Improve automated and semi-automated active scanning for BurpSuite<br>

Author: Tobias "floyd" Ospelt, @floyd_ch, http://www.floyd.ch<br>

Pentagrid AG, 5#, https://www.pentagrid.ch

# Compiling

`gradle clean build jar`

# Improve Automated and Semi-Automated Active Scanning
Active Scanning might often do things that don't make any sense, such as scanning GET requests to .js files or scanning non-repeatable request. This extension allows to filter and preprocess according to your needs. It tries to check if a request is repeatable or not. If a request is not repeatable, it tries to make them repeatable by injecting Hackvertor tags. The extension doesn't try to be perfect, but useful. It cuts corners and in some cases simply doesn't scan certain requests. However, the extension individually displays and explains all decisions, allowing you to change the settings if you don't like the behavior. It's a better "Actively scan all in-scope traffic through Proxy".

# Howto use this extension
Usage is very simple:
* Add the website you test to the scope
* Enable "Proxy requests" in the tab/section "Scan - Options - Requests to process"
* Browse the web application (proxy) by using the Burp builtin browser.
* Check back on the $tabName tab and see which request have been active scanned. Check those that have a high "Interesting" rating but haven't been scanned ("Scanned" column set to false)
* See the Dashboard for Active Scan findings
* It's always good to sort by the reason column in the UI and check the different reasons.

# Performance discussion
Improves performance by not sending everything to active scan. 

# Ideas for future improvements

* Let me know if you think of any other improvements on the issues tab

