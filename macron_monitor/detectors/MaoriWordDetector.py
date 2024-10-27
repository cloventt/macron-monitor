import re
from typing import Optional

from unidecode import unidecode

from macron_monitor import SuspiciousRev
from macron_monitor.detectors import Detector

WORDS = ['Ahikōuka', 'Atatū', 'Auahitūroa', 'Eketāhuna', 'Hinehōaka', 'Hinenuitepō', 'Hinepūkohurangi', 'Hāhau', 'Hāhi',
         'Hākuturi', 'Hāmama', 'Hāngi', 'Hāpu', 'Hāpua', 'Hāpuku', 'Hāwea', 'Hāwera', 'Hūhana', 'Hūkerenui',
         'Kahikatea', 'Kaikōrero', 'Kaikōura', 'Kawhātau', 'Kaūmatua', 'Kererū', 'Kumeū', 'Kākā', 'Kākāpō', 'Kākāriki',
         'Kāpiti', 'Kāti Māmoe', 'Kāwharu', 'Kōpuaranga', 'Kōpuru', 'Kōrero', 'Kōtuku', 'Kūaotunu', 'Manawatāwhi',
         'Manawatū', 'Mangarākau', 'Mangatāwhai', 'Mangatāwhiri', 'Mangōnui', 'Matatā', 'Motumānawa', 'Māhia', 'Māhina',
         'Mākara', 'Mākareao', 'Mākutu', 'Māngai', 'Māngere', 'Māori', 'Māpua', 'Mārahau', 'Mārire', 'Māriri', 'Mārua',
         'Mātaikōtare', 'Mōkau', 'Mōrere', 'Mōtū', 'Ngongotahā', 'Ngā Atua', 'Ngāhape', 'Ngāhinapōuri', 'Ngāi',
         'Ngākau', 'Ngāpuhi', 'Ngāruawāhia', 'Ngāti', 'Ngātīmoti', 'Nūhaka', 'Otūmoetai', 'Owhiro', 'Paekākāriki',
         'Pangatōtara', 'Papakōwhai', 'Papatūānuku', 'Puramāhoi', 'Putāruru', 'Pāhaoa', 'Pāho', 'Pākawau', 'Pākehā',
         'Pākuratahi', 'Pārae Karetu', 'Pāremoremo', 'Pāua', 'Pāuatahanui', 'Pōhara', 'Pōhue', 'Pōkeno', 'Pōrangahau',
         'Pūerua', 'Pūhaorangi', 'Pūkio', 'Pūkorokoro', 'Pūponga', 'Pūrākaunui', 'Rangitūmau', 'Rotokākahi', 'Ruakākā',
         'Ruakōkoputuna', 'Rākau', 'Rāngaiika', 'Rānui', 'Rāpaki', 'Rāpaki-o-Te', 'Rātana', 'Rātapu', 'Rāwiri',
         'Rūnanga', 'Taitā', 'Takapūwāhia', 'Takatāpui', 'Taupō', 'Te Pāti Māori', 'Tongapōrutu', 'Tungāne', 'Tā moko',
         'Tāhunanui', 'Tākaka', 'Tākapu', 'Tākitimu', 'Tākou', 'Tāmaki', 'Tāmati', 'Tāme Iti', 'Tāne', 'Tāneatua',
         'Tānemahuta', 'Tāngarākau', 'Tāniko', 'Tātou', 'Tāwhaki', 'Tāwharanui', 'Tāwhiao', 'Tāwhirimātea', 'Tīnui',
         'Tīrau', 'Tīraumea', 'Tītahi', 'Tōrere', 'Tōtara', 'Tōtaranui', 'Tūhauwiri', 'Tūmatauenga', 'Tūranga',
         'Tūrangi', 'Tūtewehiwehi', 'Tūwharetoa', 'Tūāwhiorangi', 'Tūī', 'Umukurī', 'Waihāhā', 'Waimā', 'Waimārama',
         'Waipātiki', 'Wairau', 'Wairoa', 'Waitematā', 'Waitākere', 'Waitārere', 'Waitōtara', 'Whaikōrero',
         'Whakamārama', 'Whakatāne', 'Whakatīwai', 'Whangamatā', 'Whangamōmona', 'Whangaparāoa', 'Whangapē',
         'Whangākea', 'Whangārei', 'Wharekōpae', 'Wharepūhunga', 'Whānau', 'Whāngaimoana', 'Wānaka', 'Wānanga',
         'Wētā', 'aihikirīmi', 'hapū', 'hākari', 'hāngi', 'hīkoi', 'hōhonu', 'hōhā', 'hōiho',
         'kaikōrero', 'kakī', 'kamupūtu', 'kaputī', 'kaumātua', 'kirīmi', 'kāinga',
         'kākahu', 'kākāriki', 'kānga', 'kāo', 'kāore', 'kāpata', 'kāreti', 'kāti', 'kēmu', 'kīhini', 'kōhanga',
         'kōpū', 'kōrero', 'kōrua', 'kōtiro', 'kōwhai', 'kūaha', 'motokā', 'motukā', 'māhanga', 'māharahara', 'māhunga',
         'mānia', 'māripi', 'mātakitaki', 'mātua', 'māua', 'māui', 'māwhero', 'mīere', 'mīharo', 'mīti', 'mōhio',
         'mōhiti', 'mōkai', 'mōrena', 'mōwhiti', 'ngāi', 'parāoa', 'pākete', 'pānui', 'pātai', 'pātītī',
         'pēpi', 'pīnati', 'pīrangi', 'pōtae', 'pōuri', 'pūtu', 'rākau', 'rāpeti', 'rīwai', 'rōpū', 'rūma', 'tamāhine',
         'terēina', 'tuarā', 'tungāne', 'tuāhine', 'tākaro', 'tāna', 'tāne', 'tāngata', 'tāone', 'tātahi', 'tātou',
         'tēina', 'tēnei', 'tīmata', 'tīpuna', 'tōhi', 'tōkena', 'tōku', 'tūpuna',
         'tūrangawaewae', 'tūru', 'tūtae', 'whaikōrero', 'whetū', 'whānau', 'whāngai', 'wāhine',
         'Ākitio', 'Ākura', 'Āpirana', 'Āpiti', 'Ārohirohi', 'Ātiamuri', 'Āwhitu', 'ākonga', 'āporo',
         'āpōpō', 'ātaahua', 'āwhina', 'Ōakura', 'Ōhaeawai', 'Ōhau', 'Ōhaupō', 'Ōhingaiti',
         'Ōhiwa', 'Ōhope', 'Ōhura', 'Ōkaihau', 'Ōkato', 'Ōkiwi Bay', 'Ōkura', 'Ōkārito', 'Ōmiha', 'Ōmokoroa', 'Ōmāpere',
         'Ōnoke', 'Ōpaheke', 'Ōpaki', 'Ōpou', 'Ōpunake', 'Ōpārara', 'Ōpārau', 'Ōpōtiki', 'Ōraka', 'Ōrere', 'Ōrākei',
         'Ōtaki', 'Ōtara', 'Ōtaua', 'Ōtautahi', 'Ōtāhuhu', 'Ōtāne', 'Ōwhango', 'Ōwhata', 'Ōwhiro']

SUSPICIOUS_WORDS = set(map(lambda word: unidecode(word).lower(), WORDS))

giant_regex = re.compile(r'(?![^{]*}})[-\s—\[\'"]+(' + '|'.join(SUSPICIOUS_WORDS) + r')[-—\s.,<!?:;\'\]\"{]+')


class MaoriWordDetector(Detector):
    alert_page = 'User:MacronMonitor/Alerts'

    def detect(self, change: dict, diff: dict) -> Optional[SuspiciousRev]:
        matches = self._flatten([giant_regex.findall(hunk.lower()) for hunk in diff['added-context']])
        if any(matches):
            return SuspiciousRev(
                alert_page=self.alert_page,
                title=change['title'],
                user=change['user'],
                revision=change['revision'],
                reason=f"possible Māori word(s) missing macrons: '''{', '.join(sorted(list(set(matches))))}'''",
            )
