import asyncio
import re
from datetime import datetime, timezone

import requests

from macron_monitor import module_logger

wpnz_petscan_query = 'https://petscan.wmflabs.org/?search%5Ffilter=&wikidata%5Fitem=no&combination=subset&cb%5Flabels%5Fno%5Fl=1&wpiu=any&after=&edits%5Bbots%5D=both&sitelinks%5Fno=&outlinks%5Fany=&search%5Fquery=&common%5Fwiki=auto&negcats=&templates%5Fyes=&sparql=&since%5Frev0=&wikidata%5Fprop%5Fitem%5Fuse=&output%5Flimit=&manual%5Flist%5Fwiki=&show%5Fsoft%5Fredirects=no&ores%5Fprob%5Ffrom=&sitelinks%5Fyes=&referrer%5Fname=&page%5Fimage=any&cb%5Flabels%5Fany%5Fl=1&max%5Fsitelink%5Fcount=&langs%5Flabels%5Fyes=&categories=New%20Zealand%20articles%20by%20quality%7C1&common%5Fwiki%5Fother=&format=json&sortorder=ascending&outlinks%5Fyes=&namespace%5Fconversion=keep&ores%5Fprob%5Fto=&show%5Fdisambiguation%5Fpages=no&show%5Fredirects=no&max%5Fage=&wikidata%5Fsource%5Fsites=&templates%5Fany=&depth=0&manual%5Flist=&search%5Fwiki=&before=&language=en&links%5Fto%5Fno=&wikidata%5Flabel%5Flanguage=&sitelinks%5Fany=&cb%5Flabels%5Fyes%5Fl=1&labels%5Fno=&langs%5Flabels%5Fno=&output%5Fcompatability=catscan&search%5Fmax%5Fresults=500&maxlinks=&ns%5B1%5D=1&langs%5Flabels%5Fany=&edits%5Bflagged%5D=both&min%5Fsitelink%5Fcount=&labels%5Fany=&rxp%5Ffilter=&min%5Fredlink%5Fcount=1&minlinks=&edits%5Banons%5D=both&links%5Fto%5Fany=&smaller=&project=wikipedia&pagepile=&outlinks%5Fno=&doit=Do%20it%21&referrer%5Furl=&ores%5Ftype=any&source%5Fcombination=&sortby=none&active%5Ftab=tab%5Foutput&interface%5Flanguage=en&templates%5Fno=&labels%5Fyes=&links%5Fto%5Fall=&subpage%5Ffilter=either&larger=&ores%5Fprediction=any&'


class WPNZArticleProvider:
    _class_logger = module_logger.getChild(__qualname__)

    def __init__(self,
                 **kwargs) -> None:
        self._instance_logger = self._class_logger.getChild(str(id(self)))
        super().__init__(**kwargs)

        self.article_titles = set()
        self.last_update = ''
        self._instance_logger.info('Beginning initial population of article title set')
        self._update_current_wpnz_articles()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            loop.run_until_complete(self._periodic_update())
        except asyncio.CancelledError:
            pass
        finally:
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()

    async def _periodic_update(self):
        while True:
            await asyncio.sleep(60 * 60)  # hourly
            self._instance_logger.info("Running async update thread")
            self._update_current_wpnz_articles()

    def _update_current_wpnz_articles(self):
        self._instance_logger.info(f"Sending query to petscan with '{self.last_update}'")
        query_result = requests.get('&'.join([wpnz_petscan_query, self.last_update]))

        query_result.raise_for_status()
        self.last_update = f'after={datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")}'
        self._instance_logger.info(f"Updated last_update to {self.last_update}")

        parsed_results = query_result.json()

        for thing in parsed_results['*']:
            for article in thing['a']['*']:
                self.article_titles.add(article['title'].replace('_', ' '))
        self._instance_logger.info(f"Updated list of WPNZ articles, new size: {len(self.article_titles)} articles")


if __name__ == '__main__':
    print(WPNZArticleProvider().article_titles)
