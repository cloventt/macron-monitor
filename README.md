# MacronMonitor
This is a bot that monitors recent changes on Wikipedia to detect edits that remove macrons from words.

## Uhh, why?
Some anonymous editors apparently have literally nothing better to do than remove macrons from te reo Māori words. They
seem to be doing this maliciously, I assume out of deeply ingrained racism and small-mindedness. The impact is that
words of Māori origin are misspelled, which makes the wiki generally worse. This is simple vandalism.

When they do this on articles related to New Zealand it is noticed very quickly and reverted. But they appear to be
have started a slightly subversive tactic of removing macrons from Māori placenames in articles not directly related to
New Zealand. These vandalism edits can go unnoticed much longer.

To mitigate the problem, this bot watches the recent changes log and flags any edits on mainspace articles where the 
number of macrons is smaller after the change. The suspicious edits can then be added to a log page that can be
watchlisted by editors. By casting such a wide net we might get some false positives, but macrons are uncommon on the 
English wikipedia, so edits that remove them are extremely uncommon. 

## Development
The app uses `pywikibot` to interact with the Wikimedia APIs and recentchanges EventStream. The project is created
with `poetry`. Installed `poetry`, then run `poetry install` inside the project directory. 