/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022  Dirk Stolle

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/107.0/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "70e3e26b5aa1b066b4fc995f043f6eecde400c6087af640b09660823636c175d65c0ab85d33471cb82e32b4101572dca78f511a9dd360987e4fee46cc4847dc8" },
                { "af", "457df0aebd0223013bb13d34a79b538dcb5cb71ecce5c1163f87aff712c7e24a4a40648ecd51ee5c8fed0128371c2d8833421fd98d63cdbb8d58e4c783b927ba" },
                { "an", "a7539c1208a1f7fe85072aea38486945d2875dcd2dd0836b87263015baf5f55354430957e996f2f195f950b1d930a62b4239fdecffc51dfbf731e9de50b7cba8" },
                { "ar", "ec82d2179338e8a16e51c8aaf6ffafc8eb9b27723df81963b9d5ba16a2ee9aaeafa4216e87e129775c87e769f9f80b2eeb05613449141c5c4b653986feb24b3c" },
                { "ast", "d273699f2743ccd787e5bd0e221066d659fb3cfab2042686d06cc66e87491f9107fce1dc448df7d5630890bfef1a31aea3785e6c9d32c09ec523efd62bd1abbb" },
                { "az", "e2b6e73955aa13d79db890f53aa280dda4e651ecd1072b4328dffba067174351a17222583ebf53be85bfa9b5c789402a22a9aedc959ee07336236b32a247ab0c" },
                { "be", "122b7fca75d6f2a165ba5533d3cdaf20709ebccf7da9a7318d1ab0a7f77e9767f57d33ae21b7252c4accf8cfd1c5f3c2924759f5593e7456c0ecc722e9f97975" },
                { "bg", "df1067f164ff136f810bb43ac761f85894232ea620d6c0bc275eed8eacc80ee4ad48a791cbeee129776ebe60a3f29b9d108f83cc45bb8d8ba6b8a49fe800f85c" },
                { "bn", "b67f5689ff92ce9ec8230c147ac8447538d6ee3ef835a7bf9a8ecc28f54e4a1852c98c77651a283ca2a30b17e535f846677c7e681d04acb93fcbc3a979438c57" },
                { "br", "db75b070c175954f2ef1a4234d44ae9fa7df475890606a554e48ba5d24273133ddb2fd561fcb0adb73f60ea73cd8b7b5e9a82bccc633e5edc1a3ef4eb3ec4f95" },
                { "bs", "ef199ca0fd66091094dea93d025fcc89a597b1ebceca442d9bcba25a8690ee03cfaf979c09328817fa9bcdbaa8e184e451c8ba3ba0b202f31fd2e66418b41f0c" },
                { "ca", "ea9e4a2ba939c1993a80b00399694bac4f7950374dbad0d33c983a1d28b51c5f9fa5bc78286ba33efeffadb8e6d84fd033d6427e6a8bd2bd2120a204efee800c" },
                { "cak", "550bee90fd025a518e16f69fe407015e1ad2e86e76f00fede4708a9a8423f1430c8dd4566a53b0b66c9455541ac30eae2b74c46e929ee8893957c0e9b2ef1ead" },
                { "cs", "5c8d14b92927784f4bc6232a6ea045a46e3955b8d2e69c2277544fc6cedb943c00839096131ae0d624d344c04ae500945e84e08ea0ab0f93decfe6ae9b0883f5" },
                { "cy", "4337397b53630e21b30b95927140d842b8fa87d79ddde6a1b80793ac9f04ac3925c97f725c1f28865eec17caedceb11c1a09a0895609d3564c93502935971c72" },
                { "da", "65bdb2873e02b1a04003922152d27cd6afd2e2130c349b90733c673c4ca6f14eb50e13dd2e6ad0238671b104a01d7920ad35207198533377e5ccb85f1b447fa4" },
                { "de", "d5a69d94ee552c9be773363953440a9d54a9c7a6a1bd71e2cc4a44c2a0da81b35561ec5dd41251227f7b94e7a438ab02633a48ac7e8c0b35a2d49098953a8568" },
                { "dsb", "0daf013de43d400c6ce34820215469f931c8eab880fd9e2d9cd4c5f553ac4b326e68b05628a70e84565db25216de9e08c5f1f232c95c055b52bac85b48605b3e" },
                { "el", "38cebbf6166fba7b456b3cd878ae754308aebe332f065522dc89e3204fbb44a79c8a141be51f53d3ea574fda9703b6f35b8e1991ad6a246b2dcf67865eab15f3" },
                { "en-CA", "a9fa822a6773823fd5a1733e47a72d2ab5b723ecc6a085172eda51bb139d839055d85e5180ffd1e36a4dda34c74061459993847084e1d61beaca4bad97534520" },
                { "en-GB", "5f21e317f8a0be9c12c28968d93574260b7f30058472a04fe5b14931a9104fbf6a5eff894aa8b6fd219db81313dc4cbe5b0680fb312bacb896fb63eb38c19630" },
                { "en-US", "ee197455acf9b48002d6024a2e3527d1cdc382c2c8d94c41d41f788a7e9aef7492421fd3cc35f2c40f2c94c9763d37f0ceda153506baf26df51027706b372787" },
                { "eo", "0426913fc9b9a06aaccfec7d12af5984e56cc99d35bc5a4d1f1942126f1f0188b5330e2abcccef776c99c3e8bbc4cc4fdd413b35f1c02623b719b52272f3e3b7" },
                { "es-AR", "a8309e3d0ddd228e9025dcae3f8e5a34f4dbb5f082341ad1641b99afa34b3e5635333a94f6273682c59e1728d16ec7d8acab951ba89c26cd30c68a20c67eae7b" },
                { "es-CL", "ebf5f4c705b8186cb67b05a4822fd2f33ad8bd82291008d33ba280dad9a83b23fb270f21b42ea3795f1e1aa72363a7169d671594ff27585798dbfb0c95409c6d" },
                { "es-ES", "94f640622767cbbb9d6bb53370a3526f08e265367ec13d4ae653a6bd104bf747423bf669e4b3cfc701aa966ea939f0a0844da94e8c7a9b1bbf14696e99cc4c49" },
                { "es-MX", "7ced7b8b3f8abf48a5b751f0213e43c9d4517c6ac448ecc9e1a1a81064bd634fc3e81eb53f2d8559c672f8084db53ac2678854a76f048c0d63da0e5f2c547bdf" },
                { "et", "05f69b97487dd2c66a3fac728a21c5794174dd398c869fb8363593a78d172c4c05b43ce25241a1acc3999047501b619d36bb94783c56eb19dd84d3bc9e58a19b" },
                { "eu", "07e800aee0c65d6162ef9dfb9393369a0e34a2a24fc8f45afaa7f27b191a9c7761df8fe5ac667735652aaad26dc069fdaa3de1b0250681514efc17b28e900bc9" },
                { "fa", "4558a0a177b585b341cd5bdf93f657f35c21ca2712d22db4c5d45001ef280212a9de1943d6c33f9ed5d883e21db396090329e8eadadcdc71d0bac79464d77aca" },
                { "ff", "a7f46cc31ab6c3b7ccd13f40890bf22e0d7c435d230436f16c09c032f30d2690c64b1a847f9dde2c4ae2cfb92a3a7c94a889ceb578e2efbd687e97d967289103" },
                { "fi", "15e1b97a88249846c6b390dfa37875045b618e10a83cd4aa5da4bd9e43fe491ce76e2e60b8796172f96f53ea60e3a1a73434dd91490fa4a01e9eb23961809d09" },
                { "fr", "c18a723ea822a05d7c3cffa583a972100e86ca2c037e86737ef403eff01213845768ac3c1288efe381f2a878800c9d1622234507b101209242191f61ddda8631" },
                { "fy-NL", "c485c02bc603762fd736e66016af401c36e2d1b67c224d2c559ba4b6b6e3a50a42d6526f670a5aa25353084303f21579f6b5cc8c2ed590c629c365fd485465ff" },
                { "ga-IE", "c84fe85bb885e788efa6aa7010ac2d68c18fd725c3afae7591f075532b1a3f85cc8aaeab3a9c61a9e0c68e0a888616b1d05ea85e2816de5381cd910f6107eb2f" },
                { "gd", "96205ceabe10e3701c0aeac2135d94e891d8785b7bb878f841f51877074f656f20b05f07f36df6e021567c0b926a42431161ce7e3e2aeb707389a4e0af5621eb" },
                { "gl", "bcfb19e8e28606801ff359284c00b1a383c2b01665af5c26c018b4e18a9f15e1d4dba14ecbc39f95478bdaed639171518c75b0205f37d85b3002f29cc6afc812" },
                { "gn", "f0dd4e11e8444a9b7729a82f0c109de903f91904b027c52ce456b51b429bcc9b4aad99efe8c4063b43c4675aa28e8a53a68a856e58ce57a041c4d8275a9621d8" },
                { "gu-IN", "46dc0647cb3508e3def0335e9cced977a6ae2ee4b7ee9cbbf575a121cce495913e573ed16f645edd172963699b6515c18c92703cbed6ed95dac64b47e66dba83" },
                { "he", "b7ec871d3f145e7c538d9d79ac88876070823357c5dae3b43ecf17b52688a6f42052bd488060d3d2db81b682e48fa0e526dd92a01f8c7953a5442b73c2cb95df" },
                { "hi-IN", "5187da891469623cf38c3b2b5131e5d5ad7e4fd336a1a38395b95ea4091fc679a60dd95787bd0ee25a2be756b907c9477ef660c31a4d9b0d02d35062be1d8db9" },
                { "hr", "8e034f3a5852d941f65a44d26a78eba00acdb01beb121f99cb74a29751d0df4afe09434adbf0c7a00d550a17b82ba197ec013fcff89f5aeb2b0d4bfda521b29a" },
                { "hsb", "e18eb965da607ff3cbfbcf3423cf9985c2074b27e3f136bab2592cd8aa74e8e268299c726f3f05ce0e759d29d07f65f56b250d2331fac1a3e5c7f42c06f19235" },
                { "hu", "955111232a39ef025e1536bf1ad49cb0605db8c87ab638e48532dfb24eb278ecc431d5c916eda5f74c96c0ec7f66801c63e2832b372523d3b2e0879a6e80e128" },
                { "hy-AM", "2bfa348d7c863fe570338dc0fb8d66e5938eb22b04355898a76635ebe03049b0318b1dd1fa9706b1743dbce680a8c69128f6ae278eb7894ebf2893c3105c82bc" },
                { "ia", "3781da45e07fea3243d59e8583a1097627b3dcee9fe4d04adbce7ea38926da3be665eb2467e170de12fbe52ce0e5046e1baaa028d49631c27273b808a0c891b7" },
                { "id", "a6c5a62cbf74809b78f766aafefa5a534977a0205622b06922b80abd78075afa287894051fc6da0f663be82467b8cf5d28d229d7cfc5e03b2f1bd63c7cfd81a2" },
                { "is", "3d108da15264d5c75252e7c1f4b3674f9a2dd7cd8893eb5fd5ca2de2634b1a58a51e670a6c45c752519bb8d3072b3e89a6a503b3ed57e6a7bf20de045df7f5db" },
                { "it", "019ec8988c0128de5ab899b429a7acbe15543d8d7e4cbb2757ea2f067b5c24c4017f99e4930f45a6086675019de75f73a4fff0cf62c8a07ac12c9c893bb58f9e" },
                { "ja", "01063827d2e1d0bb3eb08db2b828bb57f91696c3b060394e97c1eb7dc7e8f16486f316dbe586608fc9242d20a9afd3b9c53c4760fdf870efe55bb8cc6eeed464" },
                { "ka", "9d26e9ee841624498145d1d811ebd396b16753df79bdf7a9f2f90f2fda55f67f7fa32529986eb77272c68299caae9b7e4ac5482436c105918af8503c3f6ad9ec" },
                { "kab", "1e8ae525ccffa5b054d11a1d43e730e39ef253617abc7dc8d622de33e5e4655ccdb282289f59c5eacfa7c417eb7a1f0066ef1960abf5ff0c7d74eae40a6c6783" },
                { "kk", "f5553c3e042908e6e480f16f9a0724f1a9d37237fafcd1111101fb283ee77605b0e4731027cc1d24d27546814fbbff36f892665ea68f2ceb868f9f953dddec8a" },
                { "km", "1538c2007e99c88686a2bd81a36228f1681ebc106580940d47507df828ea4901a36124785b70078ad125a7445f5c1bc528a68f08a42452b5bd5dea58d1848ba1" },
                { "kn", "563d15becfc8c77af44f81849e8359473a2cdbd888cbb650beb700336c9de97503e529a1c6b8983aa9904e2c69965b4a4f18b746a8c57c7a40761489e5cf266b" },
                { "ko", "199f5f652f3237f9b820ab617a935b104af53eb49c729bacf176c0ad4c503ce12158ba0942a0b8ba719669ee5ec3c3389c66c47cff975e4b3e00d38efe74e43f" },
                { "lij", "9b0135b31fd20f83e6bf3024ea52cf906f49568b9059f30bc738c8bba39b47c86752160309ad41a3c9a226f796200d682235457d49e65803e24ae885924bcb23" },
                { "lt", "1fcc8f58389db46329263fc927dae487ab88f68a92a8d982088cf862f54b6ade41b52ea716ef936df0d845bfe55ace0edff40255eb4ebb91c18a9491167593ec" },
                { "lv", "a79dde0a60c98031ab00412c7535670d6464027652f083ac1bbc8b795bfff70acc1c7e789e2a22f8692b1412430bb7d42fb0271ff2427ace7361d4b99f5e1a90" },
                { "mk", "dad56badbea5a0fa564dec4406fb20ea70925d4f018800148308ab450307b35060a49f5b8f6ff1f14032da7de14f63dd51015f9ad214889da97eca62988fb68d" },
                { "mr", "2d028658e4cde78fc085b7f605cdc6ad1eeb14327a25e111f8c900a1e4cae1dfe827bb96f9fbdadac7c9a0655d5e649cc80720fdce9efa1f1285fdf28cc9bb60" },
                { "ms", "4b7e6dc8967a85c7bd55ab4cf5b15796e1b65077d90fa836d2859f38b8b4e3f56bbfdff264deec13bf29cdae32ded3afcd2f1f0ebd368b63000cf5e251c8d1c2" },
                { "my", "8cd80d443175d2695ad79d10e9334c558ab542d75d7f2986ceed300971d5f5600097460ba1ca43e3c1a26742a77d02a0c7862f8883727834861b39848f6a8236" },
                { "nb-NO", "908eab7893a6c37fa2db3856cc5533e1f7815be8b1eef49de2b1ac26089d81320c87f11d99ed97b186ed621f8d094205e198f2b4e2e9d5b1aff304958c5c30b2" },
                { "ne-NP", "bb87e48f899f3a8769c2206da94f4496b109e6569613d5f042e18c8b4221d87d5bf3de3c44c2f01eefae8a6763a6728edb7256d345be8a605e63c5bfaeaabad4" },
                { "nl", "969b7909ac4d07da6fd85e67eed8ab4a844580ece61575972b97c24f37c391431541f503ee34a00f897a62b389d90204293369426d7dc630b59f67222ab720b4" },
                { "nn-NO", "75268d18f408ea2a1150558eb6026a129b16fbd904227ceecf0c7c99bd19f1fb07612602961893d156b4b9219fbb7bc10f1405045c87a8d64a171e5debbd3970" },
                { "oc", "35e5f1bb607ec72e1bb881dd2b553f1dc5a225a7436089cf115434259f7786b1842013b4d6dea3be9719f569b0d4984a56ac7ef93f8a58dd435d55bc2d800fb1" },
                { "pa-IN", "92c6fff97e907431c07020dcf369eca79874c2dc7ea835112372d55f02c4bfcb6244bdd42732039195b3db660db683156b889a989fc33b2c4d9aaab06c2305a0" },
                { "pl", "b6e284fab8abae9ebf1cca6f87aa82306d4df1e2e6f2450175ff198f771b07fbb20514ba4f95af5cafe456bebecf62feac6f3db232ae09a23e72c6c6674e0cdd" },
                { "pt-BR", "ad2877dd0a668716a2c0f7d5a310d2483dd1593ea9e1b81afdce5558526836d6c778fe230206b6ff54ec4852e3992ac83c64f38db2dc44235557f406e7df5441" },
                { "pt-PT", "ee67def689a23c9376a8debd5822791da9d3246ec47c5366446be80e1f07e573625bb506cf64559b852d31f8486df62697d4cec7c0d538515cab3159b9f55ea3" },
                { "rm", "bc33abe18f5c904326bb36075618978e230c972d3a89669a61352012a63d01ec6d1f7a7d1a61b85c5a4f57fdc2b3815a63c2c6fde19f1d36f30ba6d3b151c573" },
                { "ro", "3364dee0e5b88867f6de1b11929dc4cc6d1592dc31b4556aad460a2ac4b84a1af2f09a4563071836366a53311afe1ea1e195ac8591d4e7e5e031c894dbeb09e6" },
                { "ru", "5190834eee3faa3fbca04b952d89e37cd19bd8723d3827ea3559b1446cfab576ff54c2020bba59c206069700b05d264ac4ea271715a1c137d0c8e288910397b6" },
                { "sco", "3f4fe193c2dc3ebf7a8d196406955899e97a03b142093a7a35520292273b2a862475b67df67f0f6d342d7a30fdb920a9c658cabf46fe2e69668be5b7777460c7" },
                { "si", "f0085844fd98d5fb76d952c9bcca670ffb3114a98860fcf4085697ab88076436ab18ead823c27e5783fa28f42460dde7b4c41a9c01aa6623dd37294495185800" },
                { "sk", "533988bc0ca15186342ef3f225e41b39942ff48559d4b82a53e206d0563c2453908eee82ea8c51762e07fc348074c5520a4335f0529170c06717498f7aa0a4d3" },
                { "sl", "ba5f63e997f330f5dc9404131c503dd182d636674d3f50da6dfc49273508bbad4f620a164eee619f035980d9f000c305c99f53d95474973a4de1f91bdf7333aa" },
                { "son", "1269e29a293248e6b5a677e24e686e6e2ce26f0a90abc024f8668e625990fd3ba282a07a9234a89d6c0775631823d58bd0ce45958d54910e2a0674360115ac52" },
                { "sq", "5a85d0f19267509207aafd3bdf652ad34b4f589ba1435d2e2d32ea0852a44c5093f5d05588a7699118b80bff9948c21173996c0e53f0d211c6839ff125122ba3" },
                { "sr", "75b70ca08693819075be25e160d86ae03edafb420fd5d695ccf8d3d786d8b805b6b80db5a358f8cf4c891d0c12c386ad73ce6368cc112e25cf1161aefda56681" },
                { "sv-SE", "5f73462913c182557f1f3474bda2a07ed48eb0d8e2f70f1d5fd86f929018b7a53b9deebf8330ce4f3a95faef3829f1efe1339e7d40af13b04e31b53d327e64cc" },
                { "szl", "d1ce8433b00512544a90eb8dc68295c8bb0bc80ab8989b54ad8c15570a4d9dfd93371159c62f50b5340489357698e9b91f666822624590ddb745179be76e52b5" },
                { "ta", "5f01c7f3e630df0c5475a977905bef6dbce9ee33c056bbde32058a0b4aaa4aeb4453da64c25020a80f0be74cb86bfe5fa7b5e0a6a9e1bfd502dd81a26b6cedd4" },
                { "te", "68ca608653449d98f8f30f069daa848bb1e1f6964e3d169257b46e9c571efbf742149230a0f808305f4f544ec65a83124d27e7c1862cb729d95a7e653ca94d97" },
                { "th", "6fd2b4f907c5b1e20849e5b2d44fe49581eb429a3ca86bd9d0e836991cb06f7c64f785d6686a86498db26eb9dd3b52828b67e0fbae80f9fc053e8597592b1a9e" },
                { "tl", "94b9bcd7ff50e6170e8ee7422705d17e8a56fa9b540462711de9eb39f2269af3113ef0cdc82f4524db84621a80707944e56cde78e5e675a4d98aa27863552c3c" },
                { "tr", "b37928a9f825bbc9e9142be06c9368dfe0bcc25373a5d6e3b611fb49807ef20af82d3eed294e57a34f3f63f98f0a786b488896b74a3f04232f34c1d944f22d2d" },
                { "trs", "06ed6aeace988ee04c7e9f78d99d2dbb9f696fffd39104cfa619bdcfb1f218e0b90549ef14940c1ad27866f996d61490031ad56b834728ee55f7773cb26be573" },
                { "uk", "a897c29117736c36876a244cc615a85d1a5bd00ade3be861418257982274ebc5eadee97a35cdb5c37aaf56bdbd2749a96cb9b4c0d04bf7d2b1f30472c1dfa194" },
                { "ur", "b44a3779f6e17b4fa904548573d1b15824eabd48a669be263af0f22be59f383ee5d77fb8de41603f48985336f9ce477c000ee916d26160a03acb5b6f9be8b922" },
                { "uz", "ceae59394e399a2af78900f0adc534d24e39d2f23050ee6176d44edc3a0785c9c98ecd0abf40f148b9607ee1a67703caae1c88d28f6c1ead35dd59839717f6c6" },
                { "vi", "a9a38734ecb79d59e77fd7e22de5ed6a585cf9515becf3971aba0bd1eca4b2f267a61e0879040da68ac49b1e1b9aa333dc6fa3a439fc695225e35d9bdb3beb9b" },
                { "xh", "bbaf488246fa4173811a7ee2bb383280442463446ecec674c34bee1e4698ac800bdfedb700dfefdde23f1a5ea6435b5e7865233882bbb21a14ba22ed0298511f" },
                { "zh-CN", "a6df80e3bfa5bbbc552dce7bfc3a0134c62bd16a298a9ed64a52fe959aef39422ba2d566467f7af5c3863ee944ca3bc2837cbfd199450eba015cb882acbc208b" },
                { "zh-TW", "e3b1fe2b7f1323f627413b0ff5f7bdf4131ed97936cc64e93df4c000f3eec29057e51fef7f0565ad4070a449b4dbbd4c7dc46e22b5197636115beac5e5f445ac" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/107.0/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "e5a2d78f85ab0700e6000108c0f4c9b526ea11a9f43a551e0003789db991ec50f774f2d66e89506367949286fe7a1b057198ee52584b4a4f2eb603d80a509212" },
                { "af", "2a6914566a7c62a74b1a2b53c40e0e09d60cf20cad30c0e77b6c38eb30d1b762ae9240c36c9a71357c0678967e5963427f23fe5e61330c176823aa7e179afe7b" },
                { "an", "1392c018da616501d172867b7d1bb2dc05d526f1c6d362f1500bfdbb621b12be766e83f27030b72587fd3d2da0b673d6a3935316f602e7b200cc16666a43a236" },
                { "ar", "d3f4e3601393725adeca8a4d5df00f6854e774c7f722ae5a3110ec11eae7c7aa1132074d803b71660dcdab4875b10085cd76bddb1d290875d33ad05d05ce564c" },
                { "ast", "5a21b46b0e771b5e2ad47e261c8b707a1e2e287ae9fd3af111364f551f8911ccb9f292fb5a31cafc86037070e3f641d46812a833b09f1f997b1ea6c3250c60b3" },
                { "az", "e5161efbe2278e60cc4f99ecb079a2ecfc81e8c288b95a864195dd267e12db4361e0a6ab7c3641328a6622f8abfff574cb97246eb1f11b10ccbca1c948b718a1" },
                { "be", "b884f793d90130e051b0013127cec12af39f47488322a65fba9b7c4cff509e6d11bfe869ed48571f3631e2f9b27f06e2f5c0319ae507c45cf50267f37e182ae1" },
                { "bg", "53d10ccb5d240443b7079a5ab5089a2bde08cc48e35c9d94e5e5e21e3977b2cd534efa6450e7dbf50d1f93c2ee8b55fe9fda694775b8c51136dc23f4f4e647c9" },
                { "bn", "0e48b0b1e2ee2d27a76aebd403c302228769ac3fabdc101e8fcce6f11f2c323ce70685db9477615edba0a511d1f2ae533fc363ba705c37533a3e4ebe04dfef9a" },
                { "br", "688cf7cac0dc7de6955cb77f2a0926efa9991e3bae58e72ab8c1a17e9dbca4b2704500635b423711c85852300c7b56574906e6f14c9eecf0fa1b52b38093e203" },
                { "bs", "3a95be32daf484e066ad0496dd13011ad2077383b360fb41aa55607ed5287566d2c28e7ae94222fc5d1a0bf725d49561318e556a287023303fb81d4213d77e0b" },
                { "ca", "6f2d528a28031d9969db9622629b5b97558f0a3ec1f022ea349a0eca146d1655ea4df8612c20f10cd3bbe80a3012de49158dcedd5f0385a3f74ceac653c435bd" },
                { "cak", "3f8b4b728dc5dc0ae684a51ed6465506187f0d7e9445c9c2903cb7cdeb57d603046cd8222fb42552620020a395a0ee91fdf9ed811f36c9ef0fd8a92691f4f257" },
                { "cs", "5d99e19e8f71ef08cc4b42c4c33f16b01e9ca3e22fc7dfbeeaac60d59c3b7367e89b9d1b39e58ca905ad2f103cad883c8cc475d59036e16d769158ff3641728b" },
                { "cy", "45386b869c725e09ea4536b3d08520baf8877785b2cfe4fc3d29a4eb5fbf7f93d6b68033b7d77d96ab2756d6fc85757e869a31382291b3520f53991439ba9dc9" },
                { "da", "c8cb9b9009b5e8c2bbdf51f250556d9d61fa4f329ab1d31366cbc94c27d1d111ab66a57cc257f905d8200900269e0b7707648d98311e20164489a586d1fde929" },
                { "de", "e46e5f8fa0c56032f9b66b419b1deaaee84cb17af474d9e649212b8fe0fbe242d2d388f5376f4c229f8629411280cb8c8b4da5acd2cb7f2f09f8b5f0aac9008e" },
                { "dsb", "c124939e499060674667229f99a914e26d04853545c52ce6afdef8c66f1ad8e8503808f605cc5bf46e1c01283fd0e09a96442c9a7fde621bb305663e464f599c" },
                { "el", "f6335b3bf155d7df95d34712101dc4344d5b0f06592ba47018d6be7da4e8695e522154a0bfca1c269b2ec19bdbe25c9de605189e6a905c4ba67c2b8e37800506" },
                { "en-CA", "de3e1d9307b6753adc637ccd04e39082687fd057c0e99d45bac057998be65e102d909e573a125eb154ce919e42aac283a0258e736559e0211e93e293aaf12ab8" },
                { "en-GB", "38312fd8e276cd57e2624e7a1b24dd0fb845125c61a587484c6843915b6577d2d53651f4b0e922bc95184a9ea9d857c4aa1645eb64d9393ce475afcfca7fb6f3" },
                { "en-US", "1287e281493aa7054ea2d2d18f5797ae093797321185684c405367b403452baf778a6b626c2beddb3839d71f305b74efa0e45a5fa7039a73bdc918c645850d98" },
                { "eo", "9b197d99e01259fe022354a7c0c557febb833ea5cb70f58487e83a7699da558a5d34aa7d4806a919e74b121b1e6dc78dc587d65fbf4b5435c237b33f638b1e03" },
                { "es-AR", "cef1124cb6a5b23a2c216f2f4ad3449980efd1c33efab119b906c2629a4e2f91dd59aeb48fd33f38cd93c117b183e4c51b9c0310b43ccc25dc8cc6c629a4593f" },
                { "es-CL", "dbdb3fdfcfc1e88b8cfb4a2b30179e3e57cf91b59faf5decf48bfa2b84b420e8c4aebc205129a4954633164287ba58128ebe3418c886b2f1e2d9342795f7943f" },
                { "es-ES", "bdbc6e2bd50c120293d24145f8737805d4baa91e0e80ad4f4c7d32ed9761228f17dbd3b9a91437087717a15167e1086d2e4d92ae12107778d190b6c925366c19" },
                { "es-MX", "2281ead4ce9aff7d29f78f05a41cf770887688375aa86768f78050351106ce41329c2ccfd1f541c30d964516f53f25967c05c0904b36792521342d2fa5026949" },
                { "et", "52f862e8705d6a9bbfc4dde9e97a96ec4bb323874cd238e70f717e3e170dc357eec2b8012ace57d448977d69c1b8d48a30c2328f668b912d281990e29fbd960c" },
                { "eu", "055a4eef5d6f2479f6a3010c96a86d833e7efe807d9a2bea4b593830a52567a9436496d14935ccf9918840ffd60e732b85232bcfe73dd4a443c0c26dab5c1fd1" },
                { "fa", "1200dd84608a1a3244cea9f57f18bb8a0f499e2400049f38d9a9957072ef6dd1fc275e922d1af4fa2a141d71bd6baa051b9423a8917d93a361f6d343175d881e" },
                { "ff", "2ea811aa1bd4f239d7407b23aa3449542ed53cfe28abf2c794a66cb629bc7259d7fecaa8c7b4b62b096b602475bf2ca3eb8fa048cf8a74e477e13a520234e624" },
                { "fi", "1a7b552f3d847df791569cda5e261ef046067256343980f990982d2b0b7a8a5d5ad1a6e8031212f7e22fac53d7cec32e660ae8580bb3de2aa9e6da1a0b99bef0" },
                { "fr", "5356d077384f2073629185dbe1dd8efb2e8ea69d7aa59e7be9d49d3ee1b31d4642879202b2f6ae7dc451b1aebced9cef24df86b9a43dd6eab4f48a21d741b74c" },
                { "fy-NL", "e39e6c38eb32aa5f64cf8370bded1d10e17dffd7b61804c6ab313e463865a5c1c91a49b29c5d526f0cab2a038c6709d06df28969ab1bc92799414a4ba56fc274" },
                { "ga-IE", "0bcd735e2739d3facace9084217623478202ab26eea9a14f9b08fc2d41677e28a8f75a0a03528467d28474c1c6294b7dd86ad9c0ece789b784c2e69e3712b3d6" },
                { "gd", "9e8cd5933a4450341e3f1345490ee7d17495db72c16b1e6cab881bd7094218b249d1927cee1c5154d38c3faafc318322b963d79c60b1b3500b7ac06051e7778b" },
                { "gl", "1daed1a0a7566227d0b5a544185bac33c9f2fee7f70342c527da06c5a1958a1981f49d417b2e1d364386ad57611206644179180407fe51443d2e8afcd8987050" },
                { "gn", "52d5b29b06a7f81879b2468cd647a726eba4d67dc8019540ba3eb3db79e1987ad182070f539634f2c84ddf8f02b9e58d308959866713982915d629b55932bb96" },
                { "gu-IN", "c9dba4c25b67f6ec936e04e3304d73205d101a70da6377340c99a1aba69540fb8b82f070e3dbcdfeacf7d28ebff1362fa1998a71888bbf50a96f59e63ad7fbe2" },
                { "he", "ff14770e790d5c06a08293488292d4912832f368428743a20aab4b911ea7524613370a5d7fe37352d44ada84f52262bdebabb370776ad530f52c19ae59449fd4" },
                { "hi-IN", "e9ca2cd210c37be40ecde18f388dee563dfbdc6234b1a578f4e40fd46e45202eb105f5d45aeab9bb016d62a998bd7a106f988dd5d2e174084769fc37663829a2" },
                { "hr", "722ed5dc6e3efa8df57e565fc016531b6e59ab3cb482492f9563d4694ea1e7ca336056514a44b73ad1c2a819508d3778b91943a1336dbfc38ca8bd58d84e12b1" },
                { "hsb", "6eab67d441b48d87985146372209605ee91f6dac6e74d7c7539136629708afe8873ea1a09b3e7817cdac2d0c4b78cccfa99b3fad1f53346724d23489702403dc" },
                { "hu", "bfcf2773af3c0ffb41fb015b824b9f0498876db256fb5cad8904617a7114929b9a6ce0349c733e074758f61c565a3d078384dbf8862b0db71e4d15d69fa28d74" },
                { "hy-AM", "4621b80d9713689123a0dc9ee1fd19d4f09f6c713d776b1f825f886decd9ab7fe924fb6e491b34671790cd445c4c7e12b5ca1ca8531f1b8ad7bd4c82faaba80c" },
                { "ia", "3aa00b9ac78fe3536f081d4da2612ffdf37d58c0e33ed41b305e98339f85675c7871d9f39d8ef3589f08d0e1ffd1392af9b2aba631fe94f093b5e29cbeaee962" },
                { "id", "9cc4ddd14c0b4802a23aacd53357d23fc0d84702d1998fa0af29509186ce54aa048ab5ff4ce4530b02b2f8dba3b426b86c44063453310257917d5c6049428a1f" },
                { "is", "bdabb2c690dc89d4e7cb6892b5a45f655d4a1887d22bf7ccc5b0b4dde2146e388f86dda1866788239ca80d83ba84e4a2af98e59dd36d627ec2adba9734bba721" },
                { "it", "d5a9096db7477bfaaff631b77f711aaf4cbebe553a00673e2c2c984b8931b3f03a16b9c986f9d75b2dfe895b60257e45f0f1fc2ff0b731f9537d39f384032305" },
                { "ja", "fd28d0cfac4cd251e077e7c46e54ea7503dd56bd89133ef3495175e237d85a44928fb5f161a3bcce31770f4db891003e4926a4bb06c9d104376c616b3aa72155" },
                { "ka", "a11f62c95d8ddae65b47c6beea11003d6c49c9c7bce29c4ff57faa5cb15708939aa5fb392dfb6df812dbcbd8181d0e85b5f86c3dc77df8c70ea5bdaa5acb9543" },
                { "kab", "7ed866efdaafa71ed36dee6342f3c4c5fe7dd983fd0128a5c110ffae4733385957eec9edcc4f173160ae878ba84c1a6286cd652016e991bc9d0c6ec9daf92b97" },
                { "kk", "370db99b907977f5643cd1bb7875fde299a6954fc2b4054a37eb47258dd7270f7a59996d60c6c7bf5830644f049a0885e7c0823c1f2820791bd733847a543c44" },
                { "km", "ab0cbbfa8d8ca20c34d5b8a7518ec52d14a04887439194337d258e10cabdd10bf5693dacfcb8b99ad389efbc9581918affcf4706f043a0b8510be4d9d9b73849" },
                { "kn", "6a25997cd459bcfe62a541b7d2968f1a9c2419d37741b536f2f242802cab1065ec6534b0bbeb58f7cdcc1ca31a6a68730c2cd13af944f04cb922fa2214cf9351" },
                { "ko", "342a63f3e5cf8ae0d510a6bf719b5ec9092a10ff593ded5aa3764f3eb370c51cbdce03f85b6b9d9a938f9fd96c26ea6475f9dd9c80f2820d9806b1a316b6dc89" },
                { "lij", "9ab532ba99ecc0114db9d771ddcc0828c395ccdfeb42dc147cb9f6f23907188ba740bf362ff7163bb729f698fd264f2efcaf0965ff913c78c47cc27eb19d1b0f" },
                { "lt", "4092ae83de2588d2e7854e6cc5947d870255c09c1878724508f2db6a1bf5e18859dbf9961d19ec5cf249afc3a2d15aada6ffd1ac4f5c855c2dd85378163d8fd4" },
                { "lv", "3a21963025d4cea1ea8b1abf2720bfa20c79edfe8d2177d5e24763edbdadb80bcfa382005d836bc87c60cda388d9d9f5341f0d7486e2e9c34c5b7e950dd64b7a" },
                { "mk", "e3e80d25d61b00c58fde972baafd01179357f9f7002442011769e8fd17ec9e7b9ca2e88e370c0c1fdf520ac1c78b6b3c7746f7f089b8886d6d1625d19361cf0f" },
                { "mr", "30fad4e6f80d773acd4abde1c3bac7fef60b0b672d4fe2e23499fd04c67a4543fc6331df8d76287b02364ae2c96213a5c250008062d4c43f387ee4d973a88673" },
                { "ms", "44415c9d6d453eeae533d5c8ed8d05b1c739c775eb4c3af6271d61e82a25fadb611fe969b38b2a4a344db2dbbc301fde1763d3418258ad08d52fe2552b6f88df" },
                { "my", "09fdeaacf3c8c8d350f9511fa1713b4c8a3cfae100742ce3412e23a4a0228d04cef6764ef8b198ae629066dabf441ac688f6245ed355c4bf5e131ed98299020f" },
                { "nb-NO", "7d0dfbbce03430b88b0c4e1b51ed7275cfe38d2908f70be8dff71faf9df8cd712024388c67c2eabba63b935baaeeb1180fa93306d435f5ce1b49f5e9ac566c5c" },
                { "ne-NP", "b122df35ffa3f8e2c1de2e0cbac1670d54b5e5eec04c3b2232ba27470793e21085921c0ff4df1dbac33eb5e5d9621a7da4d19e6fbfbfbf2142849a6a4ee063ca" },
                { "nl", "0f44b83ad861d2a198dcb9d29208df9a7546566b2e51a6d4bcf9c60f50a11cb82055d661b4ba884836f6ea9f356041099926ed504b0f39c43388257fe20ae8c7" },
                { "nn-NO", "ba7ebc24894dade11e0e7fa0a23007cb19c80a5cdc7f663a36f41f633b55776204b0a3d3a2e1530504f84477a34d7b29bb6e468dc8682e3a69c931a064f358f4" },
                { "oc", "4d91e58d09f732352ae189205e384bd2208405ad34a0bf4abdd6398b26164fbd9c5546654732788d235b7a3237704b3825f0e62f7c489a61c7e95c5d334e45b0" },
                { "pa-IN", "01d30931e34c01717932de05f507e59d00343c6fc7e2d5e98ec0ed8b4a047a70d14ad5023ccf4e64feb61d0140a047d4c45d2ecad40bc56fb099bbce7a659df1" },
                { "pl", "7b905592b39860dae8217abe96553ce9c66c800040940caebf93dd27f32f9e5759027282258794e99850b459bbf7caf055ca6ccbfa8515b919cd517842142101" },
                { "pt-BR", "c71fc091bb2665fe08e6bd940d947edda65668c0051d0eff3855d518a12d8dc1557bc4d174a56f140bfeb960ab5b14015dcad356dfafc789f652f917780fbf0a" },
                { "pt-PT", "f78039b469b178d0ffd180c1a9bee0f09daca5c3ef7028d67fbdbf273690b17f340d03549ffbf26241c5c5d3d6ad9a70e5bbc537ddb513c32aaed42f6ba8b327" },
                { "rm", "d1b399d813a4ad918468de4860ad459b27e5f36211ea686327d56002e89acac87177049fe031548f68edb8703a4de5b4f172b846be2dc34a771e391e80ddda7a" },
                { "ro", "62eaaefd7bb5e1003986dee2b375ca135bac5e7ab73643ed7f2d80cb88c09a0931d380c5ccdf6aa0fd7d2148eadc6b4f56eec4c97f9a00957ac80b38f9f1f639" },
                { "ru", "b1ecb907ebd7640f4b49999b0bf660d71e25fc40ad72f2805b2d35b9b950fbb914224330430f281cd7c8dd8764a9ddae4b26e32ed4e31c3383464f0f9def6bb8" },
                { "sco", "7c412a90b694e30f233e78f6a12523752ae818075ef53902d14f817fd5782d08f698916af2513505c42e57570808d1620def032da8875bcb43e42ed49a6a00d1" },
                { "si", "0532a699196720e3b9ec647c4f4027e647109dafcb029b3f45ed92f92e4dd30a9daaf1677558875ba341ae883f7ad28e25264dbaaa268135d49f08a05efead21" },
                { "sk", "325e44d16d0ae45ca02c332baaf5c5af85b899e9a49104465f0791ee9056f97d330c14dab744a0e906f75e905b346dfaaf72c2133be0ca0a93497fcc33a072c4" },
                { "sl", "455d42943f518d3cd306458a2a40b67ea4e9abfb9e97e1737fb0eb9788484d6d2cb84a9ba54b565e6dd5b9aabe44f12d0b5d8c28bc9f431f95a7185323f0ff15" },
                { "son", "44392989e5aa755558229e86c5750794a55af90dc74a2ffe3a0af62698bbb7c3c6c854f30c3b8582dab956e0966168721d45197e887cbe8c8413c6e0bfa0ea3f" },
                { "sq", "43cbc6263cf1b9eb65dae4834877796b2b2c6a0059cf921319ab61fac8ef071176186a5456dd41260438b9a164188c63889169398f6d2abcd5c0dcaf9ca7ee1e" },
                { "sr", "14080bde51ddfa319ff4a2438653951b6cfbc1b427f859e4d9543b36ba106cc5a52533e7ce20f01f98c63553bdd46786db995889318ff6f40d512dde33e6d62a" },
                { "sv-SE", "c947a6fbd1829761fae51db2307af86f49cb09ddc10d46c3b7f1e8ba23da077bcc07893c7f4291c09c3caf4c5a4bc2e6b95186753635d5332b64839a39500120" },
                { "szl", "71b22e7fd4e0ceb9545e5fc3c0779731070d22bd0698efb5e89a5673ff7818e4fcbb8c21f74e473d3a568d5442e51def598ef526ceac80f434d3c516a60fb33c" },
                { "ta", "333eb9d97945515f829a31f336284c5b30cf7f9a3c85b29332e19177244af2abb077fa4bf3450744800026d779328ca3e2c2ef79b2aefd0ce945ee0fa7e8f9ae" },
                { "te", "305b8522e08564a7769e2489c72182903362c67569a846e99c8a1f19818c0532ecad3e5d900306e9bc33a5690b9a644dc16e9cc112d946a5448aab61954843a3" },
                { "th", "91e5acf1eca4a16463112eb05d581b2a606cda8074a7a8eb3130c8a005a0682f87b43ce4c7ba061d2517ba63fd19c116400dc19d51a699e9dab8c94be0c05cb5" },
                { "tl", "19372c779d426a018aa5235218d2964861f6475de5187289950313620732bd23ac01929a00860d5f6a4f98934c0099ea96b90a7439400b862c1a59f1050dcfb3" },
                { "tr", "7c5a0c47eb9ed4583b84e236223233d4279beebf1a1d032ae0f7863e28070da3ab6edc2aea5aa26e5b312c98c53ec5e3437c7787ce8697740387edac48314d18" },
                { "trs", "46cd0ca217d9ccb9d167604b65d2d3ba62841bcee47000b046e7cbac0a77ff594c3997fc0855d8f959375b1891b808c35538ecbd9411f9fc1ca556499a81f812" },
                { "uk", "924bc12bb8a21a8ff6abc3c69c2c181fd8cdbd75738f3f6b240dc1ec23748753082474f19588f20dd967cbc82057275843c06372da919e8125a7095444e27d85" },
                { "ur", "bc1845de833b0335b9228610a46c5b2b9686cf254277b8da7e8a07420c88f6b10709cadb6d55d8095b2a601fc35b910d1c1aed6c128467a117e47a37ba2f7b5b" },
                { "uz", "5c274d7c08266885c07edf727066c7d90258f652b70c7586c4dd8ac0ef47a236506cb424668eb09e6844a4610b72ede818fdba9ee39d95c82644dec90724d870" },
                { "vi", "d50b4ac578a5df38611f699bcb7a683d6c5776e620ecbfabeea889ce996ba60b8afe2221ddb89e1916a4cbd9cb4cd16e5e22f662d7d8d6e2f2cf2f028c00f8bc" },
                { "xh", "bcfa6d23904c3664029f29dc02a0cadac09e625bc5ddd9c5b1c2a341dbfc79447551c24feecb0d72e998e9441763ff1a5332fc87ebbc93073b4b05a8b98a754b" },
                { "zh-CN", "89fc5ad4aa99813e34d95ed4242dc35de536c97fda9e1a501d24daf8540532fcd3ee5f1d58d525bb4111c585fdd8c55657d1e34b9f0df455b603436f6501b100" },
                { "zh-TW", "6e9d64276e1faed5e701c8bec3405ee0f5bfc71021f8eb95f086514a62aa5b35e72ff077a75b2faf437bf8ac0b96da0384109573b36036233f1ce70000a23f63" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            var d = knownChecksums32Bit();
            return d.Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            const string knownVersion = "107.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma")
                    );
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return new string[] { "firefox", "firefox-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
            var handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false
            };
            var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30)
            };
            try
            {
                var task = client.SendAsync(new HttpRequestMessage(HttpMethod.Head, url));
                task.Wait();
                var response = task.Result;
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers.Location?.ToString();
                response = null;
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
            string sha512SumsContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                sha512SumsContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Determines whether or not the method searchForNewer() is implemented.
        /// </summary>
        /// <returns>Returns true, if searchForNewer() is implemented for that
        /// class. Returns false, if not. Calling searchForNewer() may throw an
        /// exception in the later case.</returns>
        public override bool implementsSearchForNewer()
        {
            return true;
        }


        /// <summary>
        /// Looks for newer versions of the software than the currently known version.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the information
        /// that was retrieved from the net.</returns>
        public override AvailableSoftware searchForNewer()
        {
            logger.Info("Searcing for newer version of Firefox...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            if (newerVersion == currentInfo.newestVersion)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if ((null == newerChecksums) || (newerChecksums.Length != 2)
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
                // failure occurred
                return null;
            // replace all stuff
            string oldVersion = currentInfo.newestVersion;
            currentInfo.newestVersion = newerVersion;
            currentInfo.install32Bit.downloadUrl = currentInfo.install32Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install32Bit.checksum = newerChecksums[0];
            currentInfo.install64Bit.downloadUrl = currentInfo.install64Bit.downloadUrl.Replace(oldVersion, newerVersion);
            currentInfo.install64Bit.checksum = newerChecksums[1];
            return currentInfo;
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            return new List<string>();
        }


        /// <summary>
        /// language code for the Firefox ESR version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
