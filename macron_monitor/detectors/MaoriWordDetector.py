import re

from unidecode import unidecode

from macron_monitor import SuspiciousRev, count_macrons
from macron_monitor.detectors import Detector

WORDS = ['Ahikōuka', 'Atatū', 'Eketāhuna', 'Hāmama', 'Hāpu', 'Hāpua', 'Hāwea', 'Hāwera', 'Hūkerenui', 'Kahikatea',
         'Kaikōrero', 'Kaikōura', 'Kawhātau', 'Kaūmatua', 'Kererū', 'Kumeū', 'Kākā', 'Kākāpō', 'Kōpuaranga', 'Kōpuru',
         'Kōrero', 'Kōtuku', 'Kūaotunu', 'Manawatū', 'Mangarākau', 'Mangatāwhai', 'Mangatāwhiri', 'Mangōnui', 'Matatā',
         'Motumānawa', 'Māhia', 'Māhina', 'Mākara', 'Mākareao', 'Māngere', 'Māori', 'Māpua', 'Mārahau', 'Māriri',
         'Mārua', 'Mātaikōtare', 'Mōkau', 'Mōrere', 'Mōtū', 'Ngongotahā', 'Ngāhape', 'Ngāhinapōuri', 'Ngāi',
         'Ngāruawāhia', 'Ngātīmoti', 'Nūhaka', 'Otūmoetai', 'Owhiro', 'Paekākāriki', 'Pangatōtara', 'Papakōwhai',
         'Puramāhoi', 'Putāruru', 'Pāhaoa', 'Pākawau', 'Pākehā', 'Pākuratahi', 'Pārae Karetu', 'Pāremoremo',
         'Pāuatahanui', 'Pōhara', 'Pōhue', 'Pōkeno', 'Pōrangahau', 'Pūerua', 'Pūkio', 'Pūkorokoro', 'Pūponga',
         'Pūrākaunui', 'Rangitūmau', 'Ruakākā', 'Ruakōkoputuna', 'Rākau', 'Rāngaiika', 'Rānui', 'Rāpaki', 'Rāpaki-o-Te', 'Rātana',
         'Rātapu', 'Rūnanga', 'Taitā', 'Takapūwāhia', 'Taupō', 'Tongapōrutu', 'Tungāne', 'Tāhunanui',
         'Tākaka', 'Tākapu', 'Tākou', 'Tāmaki', 'Tāne', 'Tāneatua', 'Tāngarākau', 'Tātou', 'Tāwharanui', 'Tīnui',
         'Tīrau', 'Tīraumea', 'Tītahi', 'Tōrere', 'Tōtara', 'Tōtaranui', 'Tūranga', 'Tūrangi', 'Tūī', 'Umukurī',
         'Waihāhā', 'Waimā', 'Waimārama', 'Waipātiki', 'Wairau', 'Wairoa', 'Waitākere', 'Waitārere', 'Waitōtara',
         'Whaikōrero', 'Whakamārama', 'Whakatāne', 'Whakatīwai', 'Whangamatā', 'Whangamōmona', 'Whangaparāoa',
         'Whangapē', 'Whangākea', 'Whangārei', 'Wharekōpae', 'Wharepūhunga', 'Whānau', 'Whāngaimoana', 'Wānaka',
         'aihikirīmi', 'anā', 'hapū', 'hākari', 'hāngi', 'hēki', 'hīkoi', 'hōhonu', 'hōhā', 'hōiho', 'hū', 'Hūhana',
         'kaikōrero', 'kakī', 'kamupūtu', 'kaputī', 'kaumātua', 'kirīmi', 'konā', 'korā', 'kurī', 'kā', 'kāinga',
         'kākahu', 'kākāriki', 'kānga', 'kāo', 'kāore', 'kāpata', 'kāreti', 'kāti', 'kēmu', 'kī', 'kīhini', 'kōhanga',
         'kōpū', 'kōrero', 'kōrua', 'kōtiro', 'kōwhai', 'kūaha', 'mauī', 'motokā', 'motukā', 'māhanga',
         'māharahara', 'māhunga', 'mānia', 'māripi', 'mātakitaki', 'mātua', 'māua', 'māwhero', 'mīere',
         'mīharo', 'mīti', 'mōhio', 'mōhiti', 'mōkai', 'mōrena', 'mōwhiti', 'parāoa', 'pā', 'pākete', 'pānui', 'pāpā',
         'pātai', 'pātītī', 'pēpi', 'pīnati', 'pīrangi', 'pōtae', 'pōuri', 'pūtu', 'rākau', 'rāpeti', 'rīwai',
         'rōpū', 'rūma', 'tamāhine', 'terēina', 'tuarā', 'tungāne', 'tuāhine', 'tākaro', 'tāna', 'tāne', 'tāngata',
         'tāone', 'tātahi', 'tātou', 'tēina', 'tēnei', 'tēnā', 'tēnā', 'tēnā', 'kōrua', 'tēpu',
         'tērā', 'tīma', 'tīmata', 'tīpuna', 'tōhi', 'tōkena', 'tōku', 'tū', 'tū', 'tūpuna',
         'tūrangawaewae', 'tūru', 'tūtae', 'whaikōrero', 'whetū', 'whā', 'whānau', 'whāngai', 'wāhine', 'Ākau',
         'Ākitio', 'Ākura', 'Āpiti', 'Ātiamuri', 'Āwhitu', 'ākonga', 'āku', 'āna', 'āporo', 'āpōpō', 'ārai', 'āta',
         'ātaahua', 'āwhina', 'ēnei', 'Ōakura', 'Ōhaeawai', 'Ōhau', 'Ōhaupō', 'Ōhingaiti', 'Ōhiwa', 'Ōhope', 'Ōhura',
         'Ōkaihau', 'Ōkato', 'Ōkiwi Bay', 'Ōkura', 'Ōkārito', 'Ōmiha', 'Ōmokoroa', 'Ōmāpere', 'Ōnoke', 'Ōpaheke',
         'Ōpaki', 'Ōpou', 'Ōpunake', 'Ōpārara', 'Ōpārau', 'Ōpōtiki', 'Ōraka', 'Ōrere', 'Ōtaki', 'Ōtara', 'Ōtaua',
         'Ōtautahi', 'Ōtāhuhu', 'Ōtāne', 'Ōwhango', 'Ōwhata', 'Ōwhiro']

SUSPICIOUS_WORDS = set(map(lambda word: unidecode(word).lower(), WORDS))

giant_regex = re.compile(r'[-\s—\[\'"]+(' + '|'.join(SUSPICIOUS_WORDS) + r')[-—\s.,<!?:;\'\]"]+')


class MaoriWordDetector(Detector):
    alert_page = 'User:MacronMonitor/Alerts'

    def detect(self, change: dict, diff: dict) -> SuspiciousRev:
        matches = self._flatten([giant_regex.findall(hunk.lower()) for hunk in diff['added-context']])
        if any(matches):
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"possible Māori word(s) missing macrons: '''{', '.join(sorted(list(set(matches))))}'''",
            )



