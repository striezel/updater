/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
using System.Linq;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Firefox Developer Edition (i.e. aurora channel)
    /// </summary>
    public class FirefoxAurora : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxAurora class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox Aurora
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "124.0b3";

        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxAurora(string langCode, bool autoGetNewer)
            : base(autoGetNewer)
        {
            if (string.IsNullOrWhiteSpace(langCode))
            {
                logger.Error("The language code must not be null, empty or whitespace!");
                throw new ArgumentNullException(nameof(langCode), "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = knownChecksums32Bit()[langCode];
            checksum64Bit = knownChecksums64Bit()[langCode];
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "fe6394e74747ac5894be68480653b0b3c8cd53db3c30958a7131354e8e810d07e77946e18ed19ed1ca2058a43ea15d9e5ad62c5373a48817a977438c9aabcb63" },
                { "af", "cad5cf4123bf7efcb53594fe3bccce9b39c320c77586a9cdea5e127ba915d0a6c798b0c78759a672bdc097c1714c3b848591ccb67f508dd0bee905ad0cfc5230" },
                { "an", "93b4e15cad722db919f2498f5da7664ce96384be1fd16a6ee5f303e146cfc48546d252687634227d16cb55f04c606b34cddbf10be9cc4ec3d3b404ce64be8979" },
                { "ar", "8d87042f2389d0d1a510f50ca1f77163ec8d1e1319dd04391bc27c56697f9dcf716db304b5dc5378dbebc5a54785a8ac52f12f6f04497218b35e1640e8c0f9be" },
                { "ast", "f37f9b00f1bdb80e4118dae268311d3e0cd1af8b9e70b2e8812810877b4986990c20e401b9f3251bf3c05275b84e7e4ae692e848fb7c6872a95a683f184f2564" },
                { "az", "af000bab3636b642a1d319c9fde114fe35ed60901587f549b4060bb11f92af76c2a0cddea81378ea2661049e47f442ec61af77d7a77373bdeb2a8becaf393634" },
                { "be", "c27c0223a1afde6d555d1c2e5a05237fa648df073ffbebd356a4dbbc52bbbe650533bdf8aafd7cc03abbbf216a50d5ef786e84703e61c5fd549b8e68e570f2fd" },
                { "bg", "71b8530da873161ce30f26461234a0c77b9f187af48c1e291a5607cea861f22459a8cf9a5a7468ee82bc3232afbf2551aadcf989be7c44260aa1f1879b3f89ef" },
                { "bn", "847923d3e0139c4618e1e99bd6af62880a2ca39182f933446bbf80d56e554a6d3fb4889964edbbd3003843e5c8e46b0f34904b6285813f9e2cfba575a3da61f5" },
                { "br", "ecbc9d7d4bdbb53f68c669d1eaf52cee908eb1bd55456cf21cacbf7545075260851362349f269650fccce758db430d75df9ce68614b94b5920fbecf9bc0119c2" },
                { "bs", "cc77c7bb719cf660740ffd96ee5240e341238ebe07f2ca25e85cfadd196d968ea53cdff68df1d4c515d59c74df5b17d58824e6097f4c38db1a26568731364f17" },
                { "ca", "c67e28e9fd3aeba0ad2317402e1c2c8710f44254297bbf2b2bd413c1cdd61164803ca768ef92c083a67cdf1f3093ec3d9aaa4e834d0fea05b008c454c29601e6" },
                { "cak", "45cf4409b09e160b359717da6931cec5241794cd9dee7e315a8cc6759b0ae7b19ec484fd3f8852f676d2b1dc6293567001367c4355100c7c5b8a93f0340f4c5d" },
                { "cs", "ae309ee7ddb7da4bdca37307d96a5f728a2a6b0c4e311c2f8cc236782964844c6ab801f417c71a7608f31c64726998aa69be5b506ccb7364773669dd04cc2ebd" },
                { "cy", "61bda1296f4dd00ca3eca3e3877c1969965772f1d9df9f8a0cec78152e58eeabf49eb95e93a37b9bd1bcdbf107e1591724762a2c1b62c0c621219a6f11f4dd9c" },
                { "da", "04d721c77657704ebac19fd7efcd17e992709bbc165a0755703bb4292952d8e3ec6e25e73f2456d59aeda0540e970e7f05b4902582a00d46294f67deb355ee09" },
                { "de", "9171f490e89d985309a3af89bea8db0b411544c26b5ec67b0179a2b510a52d43565cd927573bc71e82aaf86b4c4df2ad5dcdc7ac4fb2af793842e8dc7a95bd84" },
                { "dsb", "dc1655c86f3b655d5019a6c969ab42d9c4819b72de84e9aac5f37acfaf914b78de7c96cbaeb9989486edf0cb74504f65f9cf53c1dedd9dcca5e88bd2ab19e49c" },
                { "el", "c1f284c68898add38eaaea9ad4180d00d494cfc3cbe6e78660f0dc3754473cc6e9d321593449637d3bd85c4e9261879d489570154615d1385e6b73bf6cdfa077" },
                { "en-CA", "5a9e497599f5fcc651d5988be0b6841e374754a45d14f69760c660a373110f10d101dc93d121bf0d071412302103e5fe6cfb0201a1e3cc9c93a0e51d4e645477" },
                { "en-GB", "4e8310a7d734d53f87d6e6257923f408acabfee19861f2ab2fce3ceebc8530caafbe154e7c9d9f55929eb46df310f6f296013c7a9291e8afe4e50d142f5eb2c7" },
                { "en-US", "2db1d3de6b3019a14a25f9f41bec2333add9b1664fd0f5ec726996512e2e53cf5f6a42a5c969b0bcbc9aaad2a30b17256949d97a375019178f029b17c8dac893" },
                { "eo", "ef290e224d8caebb1f4c8959ee415b5bd0fbf221d9401489b90d2cd72ab57d3094098ec63e96f7eb0841a1957e14f57306f31a00aa6de957591c509c9179cb94" },
                { "es-AR", "515f311d13adbb940f6beee36757d1ffe793965a63c84390a8a94d2839a146a9b0b09aaa7d065ad90a5175c49aa669065b476f7dc5453f2b39537c8174770488" },
                { "es-CL", "69312f83932e18d718b55c466ad63770e963d44732ad13917f690187d3af0b71d569dc8000a9ed0c408c8af7269dd8c9c78cfbb4ee5b4ada7ad86c80d686b388" },
                { "es-ES", "df74a6b552b18f047fadb0d895804a80bd72be8ca56f47247e4134b0456c3b7acf324c17279b2efa91e1b528984ba41074330d991041c5f63e76fe5ae25c1da6" },
                { "es-MX", "b62b5a19452ddff36b76ab38631dc6902be2209fb87643d1f363d3f4e743f63fe37bf17564bd92950e2e351c95b6b752ad9b078cbc826a3b750943110b221b8f" },
                { "et", "c98baf93929890cdb8b5f0d6b3922ba70df508ef0872edc7c84355165be27c43af793905fdf73378083dacd8854da84aae3f5731e7b9844f58b3a2d66660e3bc" },
                { "eu", "940a030a9ce3a54b8094c4bbc4ddbf7b5138a9a795d982c32566233f068619fd635ad1132eaf11185efeecdc66b6f80887517c50d0dbac6114800f5fac101d75" },
                { "fa", "dad28927acf389a08de44b6aecc2e167efded41fba8a150cefe833d78afd4ddba4ccf8fab0c715347313274090bc471aa566f749d11e55c5ca1842ad271beacf" },
                { "ff", "98ceb24b7c4567cefc7b62a5e37c4b8bde43090bb39f37924222006a69d81be8068bc75f8f657802d6f7f79f1b52c45cf47aaa7001b9d44cd17667c8dd794fbd" },
                { "fi", "5185a63fd27984dc35ac813046a5cfe19cdf6c1f5fd8305efe7f709037fd00db5cedc2cb9b0339d1091a11b8077cb0fc6ca26ec09561f793925c189d1f240ff4" },
                { "fr", "19cd7fe56590da84b3c6f02ad829e0128045505c0c04d70ab6713422521e84779444c20900a12302a11f748631a00b936e21172726db2c8bbb0efea9e10e47b2" },
                { "fur", "72f04522addb4d8859a45b0ee07ac8ef7cb92f6f0fc7b99842732e47e84a6b92062aca115331bb488d0ff7dcd641e97d0c860c0daa41ab0ca1f41988637532ad" },
                { "fy-NL", "2d48bcfc5033d7023e6f30b3fb0a62d0e56d128caff00144574192e029289fd555aaaa992b66fd6be02325ba10eaffc8f2d3829d01a77cfd886a7843e818674c" },
                { "ga-IE", "8048dc47329c02d0ad45b64c23a99095692944d4fe1d7873a0fba7e6c3adc3d9b96492bf8662ca41d7e0e07e894eab4298f71eb6d4fa223443b307fafa41e53e" },
                { "gd", "ef3a8d7f24e39486c1aeb2f90d368903b8a50405adc761d8d1dc0fc6ad2d36d4611533c01f675b85b57eec7e859da4e475148fdcae0b20b93deedfbc77d871d2" },
                { "gl", "a6f121b6b0bac152f56ffe2822cf337c08c649f1c338a0d425f5e5de9e68b823415fc96e0a425c90ce6fc053fa4fa0bde7548e549360f20eb91caa84826d1cc1" },
                { "gn", "94496366286033ed920e68111f0422239fed295ccb442ce5f642f8d3d6c1f0264c4ed6c1f23a80c088a080880ef32378f50227b43f918e4d03f5ef0474ad4870" },
                { "gu-IN", "2ba528e530ee7d5e9ab2994e128a4deb031eeacecf10f77620a03e13d198ce84b50259587f354cfe3e4a0f6d846e7a1585bfc52946c67e75006e91ba8726ab8a" },
                { "he", "8d7ad31a3a38bc3791d4116cda4fe2871640430412edc63f5bd2a2ae6c4e62140dd0bbaae1e2765f636b3c189c46c1566d06821bcf9442e4cc2d84c463a34aec" },
                { "hi-IN", "0de363b051b56e5d1970966b119fdfbc4c21b0117fcdcd278cee6142d05e12b0e69360a47d3e8b9337200140673c04893eead918e14f14fd80b6814f55ea8c84" },
                { "hr", "7647a03893b7704700d2cde07ade290ce8b28c33a5b8d1976585be5b467939174d010bf10eb790353fe279987af528af5edbf49d836031818656378da864b28a" },
                { "hsb", "7791d55c551799bd36ec19dcaf776abd6fb71c79fa67e022b734125513e69230ea4d7ccbc13a04c276aa1410ebf11ff5f3f12b727eff3055c7e958f9a85044d3" },
                { "hu", "15e3f015ea44ff4d8b89d357e4abbe83960bdd37d3af53b73351745c7e509f1d8e4e409f276368ac3b98edc3bcc3f80f4853789ace66bce6507e3978004d0759" },
                { "hy-AM", "29fad0a66ab30f71d4fddf5b9b6dacb4dbd08519bade1c17a44c55642db661ad7516715c511c29452e1a0db22ff187a2e77cca43876c1be560e23ef077bb48e5" },
                { "ia", "1ab05fba64bd2360a9d949b2dd777b5cf8a32de2ca32a0c8ed4f9639c501f0e89204be88308dd668713609bb99e225027789547649159acd96142c57165430a4" },
                { "id", "fa16d30a010437ca0c07da438560a2a0f6adf009808ddf73c746a715c09478d346d70945052bb0eb46a6a16130c87d18f45d7a6ffaaa7d80f22920f51b9121af" },
                { "is", "2e67eecb535926b787facbef606580712aacd08108584506d73e24c154172ccc08efbdb9effb38abec5d1a19322d10796c65f24a0e037c2e898d970e6d8f1442" },
                { "it", "f4b638ac5d8682a6c094338365db7d71e8bc7ad9246ff28d1fa66d7934ad84f25c4d3e78e5b5984468ef622292cff7ec1f6646f67b731ecd925648c40224de2f" },
                { "ja", "1903435db3c749618d2c4fbbdfdb4718c4569a1647d8a714089d99f12952d33c2b54c512bbe59ece64f00bc576dce766f62b3076a7072b811cc4b3ab43b07db1" },
                { "ka", "11e193501c2d3258b34618133c8dc168c326913cb05d1a451ba3903630ac7bea1a6028a81d2a91538439c0982f41d985da885e02b4166dd3cf80dc0660fc2e64" },
                { "kab", "cd0541bf6e78d8e4f62b7650cafbd8203f1898ae003de3d88044ad043117086404676a837d05745acd525d9285511834297a8f3be47789faef920d56ce7ea73f" },
                { "kk", "b94c7e2e33a3ca8bc2c1cbb32bf6b1a45f3963c19aaddf9ee5928703ea6601966324e113b93a21c3c307a22aef217899523cfdbec8850f7d2ce54cf7dea3828e" },
                { "km", "4fb7070af80a660608bc1bc8a1108e6e373fe3aec4e285eb93ce510837ca6d455e90614ae68804c4d1aae5ea0b4e4c317436587728e7d412a8b728cb4859f8fc" },
                { "kn", "1643dfdc7b2813b7252c5f9f7bf175c4e206bbc039ca27df0394d21ba8dd08bd182c536105f8e876272aa22228ec4d5cf9ade35931a06fe1e1035fa518939938" },
                { "ko", "2a472b76b03c7ac077016937cce14f9e472c75aeed27cd33dd2c00187e3bc740e9d7637f2e48cd51bca3b4615751dece4763d75e41f3d4c202d97d3698ee7ae6" },
                { "lij", "403009c85affec85307f0d17d21f7e1e0f01ec3a77f2134caaa7d5bc248a25378ff68eb9aa84a9b160dfcfef745902b92e1492ebecbf0b7a3052810d1f69ab77" },
                { "lt", "d4d9131e9dbb963d8a7bd79bc2dbb5aa1a2607d35000a4754cadc8de15b357e15f9c95a5da5fa1d4f3b22c1aca0e7750266577965c4b56e8fbf7704ea23c57df" },
                { "lv", "6a430d4b35a3d65dbe14472884cf595899c6396a8a80cc91ecfce6c7bd706d5d33aa2b8742a3c55957415d4c393c0570b221ed4a74d1f5c129cfbbfe47903b29" },
                { "mk", "c44d0b33b0ae8a04ce6a758792f467362367b7c3f51a8ac3e143dc40a9b8e16ff609e62a5169b47fd61530916af182ffd489183949608fe24918c4980dda45e9" },
                { "mr", "4a1fb9cae3e3169495099e3fb6b04d060528d01a596193225d1888364114aa888557876ae87630610cb527d88fb471444e6dd8f29ea69c7fa27c885b270d29b5" },
                { "ms", "4cf690a6006a24617032ebdea77b2fa0190eff0dc212f0ca84096d4473f5ec3f73ef87f8a1fb52de984a8525242d7464d9a5f85f1436de9ea0928dc3af735025" },
                { "my", "0d47c359fffad8a07eb14f2a6f4ff831d53ef2d852d68539708ff3856d032857261e67bbc53588d7a1b4a2223d63c75f63fafad6eb251186d2d1ec37ef20a7c5" },
                { "nb-NO", "3867b3019183812df109421d6b4e7c6bf40794e2b819e33b423e98a9c22e79623d1088903196eec9dc46455f5049ff7912040a5aa616ef24b3c4462479c501be" },
                { "ne-NP", "58a5f359ea3f258eb278a766f78af56eaf2e942ff6eeb041d389b936abed358bccee173c6dcf3564935f1c1d58a276b9dc82b27d298019a9687519d2f406f05c" },
                { "nl", "ecc76a1293333f97a0bd76e9f82a48fef699451b52e095dd14f704f9b51248e1f637b5554c6900fecf1fe529dc5820ad64d203ced00bb3dc362c869b16a9f446" },
                { "nn-NO", "0107e26e3a8a67f33bc41ff0ba5ab559fb95b8b8dd571aa19c1fcb74d5113f44075f625647d3053c747655fbf7546239bcd8c018e832e923147c73c8e07f1ab5" },
                { "oc", "d95a58462dc39b2a0a5c3ef7d448acaffa3d6c31cc32cbdacfd975f4e6f30423b8dc9bcf0d98059fc44a88facb6d4dab025748522dccbc887d4b159da7ff3cda" },
                { "pa-IN", "a5327cd4ab26db9bc5439686f19187385e46855f1c3aed4d48dd8a496459cec68ba102a0e8790e1d81250ba1348739e2bb4a0de15108a1aac656635261fa8a83" },
                { "pl", "2ad0b6bfead54ce3d6bf9754f9104f7dee6a67df8bac89e4e163a6e2bc496ee5a16d874be87716a9445f3d9d0900d0a0331c29506ce1207aac17375db7570623" },
                { "pt-BR", "c97d0292026a78dedcba4c4b6ade3b1ec1f141bba10913c6a4c2d75e73398b047d69bc03e300e69abf1e39868150c129ff17414310ca75d5a09c9d03ea22e8dc" },
                { "pt-PT", "3503fd5b41015c3e195bcb45b850389957b3fb9c6ac2633a9d82618b024587d91a8adc640cfdca807acbf64e159c0d2fc3126c6e2efc2f283d87178e21b1e113" },
                { "rm", "7d28bebf8e86fab0a67169c608f105ca16f4bc903edf3a2dd7abbdd1fcaa2d838ceaceffa414ab039f030d348a2f1bc57c759bf294de41821afa020b004e30c3" },
                { "ro", "196e6efbba0eb7ee8f51a6b9e2c4957ca325c50b4c760b68a9fef73172fb03d780b25e25b5380aee479b6ae67de90919067d5773c36227cde582a2760d48f621" },
                { "ru", "9a66b13fa820d3c7e331477571c769e0066b3f4b6539a4ace0a80fb48e6127c469eb8b6ff516ef6e6d7efb7e9edbb141f029b2de3bed4a9192ebb5e53065f203" },
                { "sat", "0c05090bbb4d399d3a852d6301eedf35bd991ff3bad0e0f8db442ccd68b10e27b28184ea9a84206b1fd5b885f8d525d0636ece9da0b0cfa98a2dc09e38708244" },
                { "sc", "da223b81d3f2d28db9717e5cf7a275f6f2b1403dac333bf10fade64e636c22888c89881922a5696ae9dc56631f4c8049327e7ca71c38e8d05a85878dd77db223" },
                { "sco", "21b02a19d982f54b82986f8f152f4ae37b24fcda2060dc84e1d81901d1cd8b1f6530b2221dbcad4b18af9d1086718df8cc0ff18a8377633fa9709575d3d3cb27" },
                { "si", "adf5f4b27f43f2e7b1bc8c8373e1a9d35bc103be9603a2c78917196b98c421fa3af956add94ce5c8dc2476c6f11bf6186e519a4abc58a5570541dac490da13ba" },
                { "sk", "c42607cd06e839fd52813247aec16eb12dbece1022f811bc89925a7de85896d6eda3c98034eb742732f5ab9e6a88fb4964ecc2f1f08beb51965afaa0ce1fbb57" },
                { "sl", "57a9d01cfb93d0fea0597c804cdf80d4ef0501b966981d1e395f49052bdc7eafb7eb741a42d2cc5a56d4025d57adfb5d3a3999a2ba712f768314bf5a3207159b" },
                { "son", "fd5b064f5650e5a2069031506f02d76a3cefaf88c719a954cff6f1c813ae4dc5532573c46c6c0c6c33ffded467ff588b68cb55a81920988f9486d0b02c4a564e" },
                { "sq", "8a71aeb7d4979c6e127915217671699437b47f6ee7eb889df8a6a00d135da8f486c302adb20a52005254ef97337e78fd877540155e880b7410e5cfc7f462c426" },
                { "sr", "2294aa9ad5a9a48d58cc735e02d68a0bf14c384a1b6ea990bce68456f3e8622d9cf19c0a04416b443636936320d06f47b997c447413a4f1ceedc72c32f580c18" },
                { "sv-SE", "5e0713c0a8d1f441c15d39a69c2ccad04f33d2b8957050d47cde30a4fab716bc0f36658d654fd00e08738eaa43aac283ecaed718a17289ca56daac89413d9c93" },
                { "szl", "906c2c9da71c4dfc7e462b1de2b3760cabaffe8c1f24eff5dfe18913f2ee9d292508e515b24018396512168e898d3a22a348db3b085967e015c1ec7083208827" },
                { "ta", "ebea16abc9c17497aaac57356b9004d3576ffd4f0cbdfb747d93d7526c7b1068547c1e95da8048acc4a9a5fc4baaec11739e94a527eefa93be912f80f4e5a904" },
                { "te", "9a53b9351ea8ce2de0ddc9b876c5c1fefc73be7b95556e751eec9ece0dfd710b7fb45173906ab8b978cbd9e0a7f1a77a655ed18e49117b1503f3b9ae135218f2" },
                { "tg", "a7a258e3a1915d822f5ead393bdc0bb87f0f10590e87fb8f740f490f7c167f4eac1d85272b0ca9a52d64338f2a11be795273db98ae9b146d17663f15f602a9e8" },
                { "th", "f6e4c8884d19fc46498d957588a88a9e67b9bd05f1ffb7eed1f8335e4268491125b2e2cec6da62d6e4b1a6967de8ce4e184add0398277546756c79741ce69564" },
                { "tl", "1486a8924e4c1e61e17da557c3e678fa0f05eb93538e8ecc2f7a4575c831f7f4b9e592295fdce66785d88924103a625f56e1b37566e35fa0a42424f43df6ce48" },
                { "tr", "e498b04e4e7f05f1a55e97a158cd093fc103e14da459723282ce90810016918615af2b3b632c48e121d9cb13250b82f7f8fb1f8abe632aa763da27b04d193faf" },
                { "trs", "5463ee68dd01520c70cc3dcd299d4fcbd20c6f920261d28820195308b52f13ddbf863b39c9d66dddf37f5fd32926394cc0b53036dbf192e7d176ca282f70f4d9" },
                { "uk", "c3f4ff2655bab8803c056409d271be79c7ff043a8f14aeccd6e0c7c9e6d7bb6c6780926878e0d161fa9d2738939097730972640f9a1e8b90ef2bd35a714c95f4" },
                { "ur", "bab70d496d8532de9d170c15a47bb38d1bf32b776aa5db491c2e22a6deccfcf3629872b6ac46b7da60f9f49a2f4d7ba2ee5246b54eeb6aeef7c4ddfb64c2cca1" },
                { "uz", "891dc22b7218ddca317d0569c8b6a28ae28f0f9e01a31303a0eaf43f69a065fa8eb833bcda7d62a44671605e4bb1f8ce785336e04ed33cd1e3ba1430cdf87ade" },
                { "vi", "9c79ebb219882035fbf615c04f0cdd9ce88e72bc0692ffa76754acd71afcdc863fb6dfe793171338ff61dace8b942589e3167ea2fbdec21cbc0547123250fd87" },
                { "xh", "d7387287bd6226d475c7b9917ad3c7dd8f6ca9048165319568dd1c269a726f9a2573f50298cdc93e42f440dda09a4ac29593107be8acad4eb53646875c134e9b" },
                { "zh-CN", "9823241d8ccccc760bfd0fa5fffc491bcbb727158bb73e56090f69aa7c9b10e3adb83e7bedab2873c3a36697af83014dd33d4e42c2638d1bf2d6a7175ab906c1" },
                { "zh-TW", "a044a866e653052d070ccd1affec5569afd7981f39e71854dad77c66ea32cb5af3c916c82407b79f75804912a8a150e983c2400dcfab5816f721a341566b1bd2" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/124.0b3/SHA512SUMS
            return new Dictionary<string, string>(101)
            {
                { "ach", "c1df94909ae7ea8605b7f5434f1352c317f82ff8e9176b5bb4ef8d5cf14e71175ed41371f467d480eac28b20df70fa671721690eef0b944b1268f73cd5f08db9" },
                { "af", "3d3a30cbd0f4e42543e4c9dee524bba94cc50df47425067759dca6296003dda76c2b2d7ec189c921d310f6593594657192dd8368540addc52649f37c2027c7bc" },
                { "an", "6dfc9a6b40eb1a13df3d2e09fd5d3785b77927f4219173bccc2f5a32b4a287ecbac165a873e0a4406ff8ff4d16a658a10c203c1289122d362331b8690fff471e" },
                { "ar", "2e4ddf5d5552e4d88cc047d5c21eddabbc9d7feb98f4144c8ded548e7463722a765629d269326cff59cfcc32bd61e80b18a149004a837d45f483fbc415ed9f08" },
                { "ast", "0a5f35847ff0a7add28a92ceb295a0930106d055a1150baea9389f9d54fad68a5db8aa406dbef3d7c97aaba4abb7653216d5a3afde7eca53131492ae6a2e1774" },
                { "az", "f39e597e092f519f4d88a0298c7ba1ccdeb27a2605d2f9a89452855491f5aaf75065f50382be5dc969bfd0c17a602022d01b5663e3f5dae9553af1e2b648692b" },
                { "be", "9d91098b674a05790deed2504a8383334f6fea016f599621a755b25169f60bb5432a77f36e053ec3c4a999861fc4f66e538d07180c77d32830d30b2a925c8ab4" },
                { "bg", "41c7b5024369f84223f069f8eb190a821a9fa69722dc612f46e9f40198f6c5f6c4f0592e919a3b5c0ddcb380f42124180cfb53e17df54c7e431b9d1e4a698499" },
                { "bn", "ce7914354365c8c573eadc47051a70fefae95da3b462663012c7a26113d2cb9ae59f69cece302d8a10ae8b3995660d1a441b74327ba44d8aec17798438f1cc8f" },
                { "br", "1d26e29f123ee9fcd8ee0d5142db2c00b9995e80b3251a9bf64c410484ddf09614bdfdc39765711c967a2504ffbdf3db2c11b2e2cf707ec35a5a9817e0f785c6" },
                { "bs", "ac89060812589bf4865e111bfa37d57fff4a73287b9b4dedfa71638bda446513c416eb66c1d1e2820b425085379d501ee717066f92ac2d8d7a4d50f03eaacce6" },
                { "ca", "194df684736e1aa5cdb953c05e1145824e2f73dc66d91eaf76d5bce6f787e0fc7495f5ca8fe80fb55a92bcc9723754fda2747a22c2d6cf4398cc0f0576aad970" },
                { "cak", "2da99e83c25d713782af1d43a115620f639f8a3631f20e47896679b8f970287d374685279d3ab9b9b4d55173ded87c89a7faf5c76fac5e680e536a101665a77a" },
                { "cs", "ed124181b3dc7ce80cbb6de5839c4f131913da9883e5f2e578acc7c41d3a8fa05cd7ae28f5e7d7f8fcf6612a8511bcc6343b93ce94531f9b0722d6a43dc700d5" },
                { "cy", "b6a016157cbd23b963fc50969196200aaa1d6268c773fbc58cccb21ad488075da4c8e3aaf2e11df7b3a61b922caaec4bb3c091cc8a25824bf62b8a8488edcbcb" },
                { "da", "763f518f05ba5b0bb8ee73367e28f9656c7aa58b8388bd1feff3fa732ec5258d1faa7bc0e242b673c35e2ecad3be97df499db9e6fd3e4894cc4143084e8cf990" },
                { "de", "c0e1134409fee5b4e0b7f537614b8af854787fb469cb95bfb528345603b0c6db063bfd0213147ae5b90002bc2757b45729c91d02f92b63d20fed1013c5ed6880" },
                { "dsb", "a63744a30846e5b1a4e4950980de13a642380d6aa470b0c4beb2629dba9cc8c47e24ce8ca849304097b24741f079eb8d942d6d87bc54e9fc3309e9e540173735" },
                { "el", "77dab2272856bf29a01b0b17c03ae596a665f25ac2be2e1521511450aad29a5ad85476d197b7d68e54dff215ef791bf265bbcb5cdc09bd94dce2f4f92be50a50" },
                { "en-CA", "84f128bc28e57f1aa402eb088f4969d001d9799334b41af8e54485fde5d55cbe98950a73bb8cb6b5ab7b766c56ac37048cc247940894c0feaaae189182345e47" },
                { "en-GB", "73a6fe8c5e904cc047a583f3539fa25b42fe53317e464fdcf2b9e129b38a517a47129fbdd0fd406d1d1eb39244950384ccc3f3088f63eb3d4dc9c0aafba76a79" },
                { "en-US", "d46feb2be1da5c7111a2d4dc2594f7be933a9b950a73aa645aa13cea9683cac92c2108341f5c48c9f28d8a2e7f15523213c7fac9f978dcd008fbc65a3e519d65" },
                { "eo", "2b4c7bad3c0f150b9aa3361bb75c1f469e052dea04e8a75d04723955483e2aa32c945ec4738569471deb82a1b27909e3504ac1cf545076d546e465de46087c09" },
                { "es-AR", "e33abd52676ff7beb4ce28283b1a415406e4016d3b99f6478248dd736d130c6ed8c3a55652a6cf6e1b8bcb2cb0825dcd677d063dcaf7f423917f974e120165cd" },
                { "es-CL", "835a397ed3b9db8cdc1bf3842dd1c4ff9c97f1e4640f37117a23062af6f312b1123729401f92a54874f13ad0725c9b91f00c07baf856cf9b086ffb5e52478a6c" },
                { "es-ES", "b92833ef3b5a7c2beb3ab644c16fbcbd0d9030f91646c7dbb85684da336a0589d8dbf2d66bd11a278288924961ba462029067f73bfb28f9de1f366acb07feb2c" },
                { "es-MX", "87c644ce38f910249a47ddca94b95daafaf14d06015cba12eecf73967abc2432df53eae5fb33366d33fe6981728ad678f9de796834721caaf9f5ff072db41247" },
                { "et", "dfdab7dd20614ac37b94ad39d673f52e3e249a63e1e40bfa4fc6365a86eabe7ed0d30a1998c8f626a657743abfecc00d69a259583cf07b1db664fa6ffdd0f8c3" },
                { "eu", "42c9ecf38ca3f95a8b4490622a99b76c4c718aa9d660660cf8cb3cbc18231b6e551697f0544718e528a1375d69fe6ac0e82889bb4d4ff7033bf1cbb3557e1f81" },
                { "fa", "bc96e143bb24f9d447e1e6a51208fcdc062fb03adfcead49783df4f4942a74d5d3e47596391028fd19fc4d26524de01b2f5c5753eb828df6a0004883fc76852c" },
                { "ff", "61fb81ca29337a96db3163565e1f641a364d7c997caf87cc6845635892ec334b4ff65216b060cd8c4be3765fbf05589930700cb227f32b1bfbf01040f08d5ba9" },
                { "fi", "59d3244fa980ee257758d211a7d17898e4323b48fa0eda0f454a411abcd618c4b0cf3b7f21ec3b7725a68a760388b484a0bf204db10a344cf194bd26fef13838" },
                { "fr", "53d1c3542ca30893923e84130e5ceea88c4f547bab4ccfda53dd1ba1f6fbe8360d95cb47558d1c709bdd3969fd34efcc69bc59338920055d9fa2b06d83a15a73" },
                { "fur", "7e0a67ab23213201cef393fef1249a85a28dd27269c4c602aac5910848ed0c36f125d70ebda15ddf9ba959298dd8377d8418825d51381d2af4f5016abd21abf2" },
                { "fy-NL", "5558ae570dbe72ceaccdfc53cf7c84b9252ff27182b84f3550a48286569d842064b45b4b3b63d4d97fe50f695ad38a0ea0aa7d59d05a45090b9f69594d43ae89" },
                { "ga-IE", "66ad1dc6ffe33bc74f631ce895e807c228c2e3f7872a92fb5d25c76f302494386d6a5c10ace41ef675124a06b70bc68839aacedc5532426d90316c104714740d" },
                { "gd", "54e842e7760c7567909c4f6af425010208f34098d0b4ddd94c06b461cdd345a07d536d1a57798b03d6f06274039b30d8b9f43ca33f205db5d28583b80dfa388a" },
                { "gl", "610772d79faefc73422e42d45849c44b936bcf5e9af63da9d026f3555dee091d6a6172fb2e47ceef3ac217ee5e47f96cf0e213c2421f715463601e6cbb9eae8b" },
                { "gn", "88eafb2597a6e433f29926ad1fda1c0657b6d1bee8f71704a5cf250627cc957955d658e135e93310a661efc2cd7f23d872363511146e46786bba32250980f896" },
                { "gu-IN", "bad3487c1d2108f4868bdb1817b6fe227d0366382a3483c86c70ac51429cecb2ac1c981c00b1a5fb469b46c6a1b5f7dc4f9addbe6dc7610c9ff4c73de283a3c7" },
                { "he", "1b428fe5948e45ee5670efa4735351ba1d64fd0dc1519815a2529a7ab28ad0bceffe272e6508c02d0dd5fa4857bc817cf99b511f146ef28421525a8ea37ef355" },
                { "hi-IN", "8cd34ffc3ba5ab3dfebd4cabceb86b2fea8d951ba1d157d36045f1e066a7b72800ff358db190927b871ca9567c9536bd18ee580e66372fe081e3ed761a355fe3" },
                { "hr", "7f9556000b8167932b412e44d2077f49c5b1619b98d2faabf557d50c323335d9de7ee0fdd87bec508394696347568813807a575bc3460fcf11f4c2015d6ff54e" },
                { "hsb", "18cfd4580b20b41ffdd29a0bd1da231a6eecac47f60655fe2a0ebdc57e438721821c680c089977057a41d456d3906d073a18f2ef2e21cdebd3e997ce1a9df571" },
                { "hu", "01a4b6769465a3b42a7d6ba36e3d96a461a6f9dda8c5dacbe5fb51d148ff36342de9855bd0b0181025eaad89ebc1a6f127d6ada3f083f784a0817ebabb2fc73f" },
                { "hy-AM", "4b2a2f13ee5af4886538cf570b8a2fc6728e901e750b866588966d13126c469858d2e5bf920aa5ff0d626463cf00b25c3e72151e520f244b5d452fc8b6ddafc9" },
                { "ia", "bb6eeb0d829df85233d74129c03e66ea060707bc155ed1f0dc96abb82c09987bd4809174c8b6452f0085aacb7799dcf02992ef30e6b03ec6d5a0d12fb00b2bb5" },
                { "id", "cdf612f84c2aec0e7daf5c9179163f221232b32b8e0659d2b73853bffbe2d5466e3f28287f64c2a15b42da596024587a02182a63154cc7ad55cf21c88b914e34" },
                { "is", "942e2c907491d750610662a6d48f6179f45b2c292556332d4da12ec64f81e1309ff3ebc9efca37592dd4bbac73ad75930a86b832bccc22fdcab6b074600a6c9d" },
                { "it", "cfd24e1289de1f57f509a9bf333ec8ab360624c155d79a3ad36b739d4fa35e5233bdaeec5f6d998186f3d18e236e760c7ecc63b1d073fdcbc360540ea82be39d" },
                { "ja", "77c47460b6c4f75b899e9590eeed469c081b3d37ec09a0597da32a220520a302650d1b10ab4de90197b72b327da0868f1b39adf787c023ccab89dc84d2f7297f" },
                { "ka", "5b8c9d8c26267e4a62a620f81be1f12c179cbbcf9c1a5cc1508d1b973d6693436c3fd57b69a2f8152193dfd4759d5a58d1e145455afddddc0fa25c00668f541c" },
                { "kab", "c6e963f403c35d02acd7a0a4759773ec58218dd7ca132443d18891604c0f998a4084d9fc592fec0c7e4b3a3f708c4f419b3aa814b33e58dd9a9305ac7c6657d3" },
                { "kk", "4e0547a11f267f57e9bc56e1f4f03a1ddb92b61a5d51a9221fbc1339f0df268aa4ad4f07a23a039aa1ca3bad12e65cd09fa3eb81f67a397de4f7e5480e06c5ad" },
                { "km", "26e0df92d4fa5b6e89d5641a1784ed57badf37002ccb3f99985afc27d6c05f2a79f9f457fdbb855fbb6e35eb0af9c7e74861599701d7bf6f0cd01d05dd51f6c9" },
                { "kn", "c6e93188b4f87471e2d8d91b432d8389248d2fc8a6541547c9ba7f9672086ad357d1cebafd460056927e88bd75eced055fa519070b2cf561134b71415c900579" },
                { "ko", "639dab4f5b373f70d013900182c6513aa9f28cf9b1ffc27995e5d3a1b577ff67cd528d083541bc4f4f4144fc257f74c826088895c70cec191efa3f18f612550e" },
                { "lij", "123164408753d8bbf53abb619d83ec8229a60cb06355b231460467e3bb63c252e400a8fa31f4675720f63b75e7e5b0473476d2ffe3df6ba465ffb6701a601451" },
                { "lt", "2c1b276cacd6075411a527fa5be1164a3261b8280f592763de81c0b4c52916cb3eab0cae416cbebac5bad35f0f52b17e884e3db6c386085424e1beba96ad3990" },
                { "lv", "694292ba2d4b0c570489f070e483d44ab7d6bb46dd1c0808430c4efca1b9ae4e5a056eaa7e0742cf3d3840ddd5ca8ec1fcac5e05d8b921e42426a3d3f0a3b0d2" },
                { "mk", "37aa50cbc00fae590eeab60ebee225c674d2daa65abf1ff5b293978fdfd73c2c1054ae069f7fec532389a7fd70474e89303ff388f1ef8af719af8ffcf3cb7c33" },
                { "mr", "5c2a6d5b03d6ba4da66bf40bb1c9b6bd1e993df591e5289f9592e86f26488ef1a9e4a2a7707685e4c4ed4239e26ef503d81f5bdfffbc95b0ebc501dae5e590d2" },
                { "ms", "ca8cdbfbb92f62f8018f4ef4664a9403898a3b6f471f9a8466a755f8ea590002489343e67624598460a06282f7e8c0657d21c281c5ea7321dbb3a1c4e37c4c05" },
                { "my", "de65a7c4fbc95b3ed08eb671ed6ce0a192eb9f7dca87bfc7b1cf9bcc6298d955bce660be0dc43951c9d2ae5fabaa4971109e822933b2399cd48b6c08ba3011da" },
                { "nb-NO", "563a50da4cf6b4897b2862905eb91a31d27c66e46b26692f3f9df5430d8e23ee6c772c83f6d7cbbaeb69a474843ddaacc0f30393b97f05ea09e049520bf8e0d2" },
                { "ne-NP", "0a8fdf760a4439c9ace9614b4713034004cc5212f8cfab1f30304fc894c6cad83a32ca5e2100e2409bceddc89b93d377ae0aaccadd3661bf1cf4e92a1903a2bb" },
                { "nl", "6bc249f82c19669e28b2ded640470965e5d60e9a17b8c66c6b1831049cc25b84a1b7bea9ebf5162ec0717a2a2dde0a1b6ad27c077c06c76e48d285f0fdb9ebb2" },
                { "nn-NO", "3484d3acbc9711f32a9c16a6ca0a084309ff09769017b145c42484417717359a6bf0e2630b8cb3d2d979963acce3a754f41bb331a651b1b0dbecfffe5438f7ef" },
                { "oc", "06a90df3d405eed33fa8e321f068508d89b05e043f52d07a026668113e150d9b9abf1ae65e1be01259a5acd899d960ce46f1beda92b6a662911fe8d67dc5c9b9" },
                { "pa-IN", "dcf03b7fb6b4fdaed7b3db713c196753f7c0edaab1403e5713e387ae86177c7b19d296ca6d77ce6b7166db389c6c3feb14b3a49864b9e8255e15efee08200003" },
                { "pl", "9f271b664d4ec53f1eee431a84b5e6734e27895a18f3d1c40f039da2ed450573b55d0a54486351b753b6adfff924b38f6827c6c82a28c20ac02518865d811bb8" },
                { "pt-BR", "5b80becd9bf87daa8c36e7e1764a6978f713cbb5d30fc7ca2d305c7b1e1a1311ff783ecf86a66d3793193bfdd48e63c59772c9124824184eb41b6fe5b7a06e82" },
                { "pt-PT", "8e3a75e266c7efa34e29dd29ed7d682d75f648d8f50c2b295448624bd4123955e9bc584bc20b9b2cbfdee8bd5363a867432e86cad009919a9a08e9ed3fd3ad4d" },
                { "rm", "d8b24bf5d4c7571cf154ae1377031ffcb72f7039168e9a1870b6a17dcdaa8fd529d2c4c96db30d806db61b60d40fad3dc3ceef4f17f64310c0eb65e56dd2e13d" },
                { "ro", "5d6140497a136137058c68384661567270070ff884a21d808952f268611b6b678d8a70f2fabc6e7f2eff2583613b942bea765c90e34c989982bfbebd416e4360" },
                { "ru", "56c3b960e0343c1720142ea3e1974e00924ab926730afd2fd530858e5a8a95946e90593810119bf777605d400851f0ca35ab0ac36ad6bf80df3c44e57ff723f3" },
                { "sat", "9c36d454f8db576e6eecd576e0f97a706142cbd4a22c3e2f19627d6e20586418b17f4fc32bd68fd4e6f0a395c0f7cc740cc3d238abb9d3f6834a2cd3dd97a484" },
                { "sc", "dd2ffc7c359aea7a89530c803d65bbf6e3e4e3b6064e789855a25227336a43ffb302d65619c2c6b314e96de1fa8171a4ef6940f88499c2186ea216d71062ab35" },
                { "sco", "e7a8e916464f45e97dd0712a3eea8d9da84701e58444740678d538ebd6bf40a18440a45e9fa1b0e9e96927979acba33b35d1bdf9447240f2bf3b4e0bbb4667d2" },
                { "si", "6789cd09013f4042d6fbb3384195053c0ddd352ff2060b3768d98636525d67772c5006cc9959281244043acb7f4f0a989ace8ac4e4f1626b7fe4f33a9c346f20" },
                { "sk", "ce1406ab89aa1f910f68eb676f044e1fe0e83d7da00ce971569813bc78f5e63b3e9849650686eb0d0220f043ef95a956e28c181a4485203b2424c0e04bdf7540" },
                { "sl", "4a951939857d94ec90ff08e16627ec01b020833dd5e3ed011a32fef52471a8b9f8370e3b32e63908d95d40e3f0c88846b199f5c52275860ac61401669e228018" },
                { "son", "4a335438c1c745b190976692cf4a75c16430e60f739c255178ab2cfbe8c9f63d580db8146e61203edc21ca1d81f18f09fe839063937200d2932d1835e23b3d1a" },
                { "sq", "3fc9c730e2f6f2b9b02df3bbeaacc869e14e354d7a54d4385c34fc74ab85e2e2633abf2e471bd64df8e073ba908ef4bc29ac9faea0a092971bda2c31b8a23bae" },
                { "sr", "3794dac78717eb8ccf893c829d15286afaf8ff1f4849128cf82247b24e4a86a91f98512a518dc9fe61da7df9ed9030a63a5ce127a7a90520ac2934f0c486c167" },
                { "sv-SE", "738aee9853a692c344c68dada2c7aedc1e3d776b4cff4158f6a2a5e99134c3a1370d47f1bbfc40973c3111efc07d70b2fb5797a068e98d0c64463510807b6f89" },
                { "szl", "faa690ea4d175710871b953ea6fc5fea88e156f6a0645bb0a3cba4cdb91a10966beb64efb1bd1b965f5af03f8ee4580aa8bf1e2dfe45626a68b6186eb784e933" },
                { "ta", "19d04d1a03f0bad1ea8d20636436f88d3b5f4c265d816bbf276da0c7649db226b4e3007aa73f3c38c9b90197d2b641c474541e8f6ae0de7f6b22970d2a8f3c8d" },
                { "te", "df8f3932d5a713018158592209ebd27a94b9885b6cad190f701fff48fdcac940532471973f9c0669cf3cb5ebd91a7427fbb40dcdeb5deec3abded15b5d46636a" },
                { "tg", "2fd2d7b1b63abc6ea514e2dd10b66a8b6250e8cbc3c2f6c2367a32bda0c4fcdd11b281fe1f762adf4b5e4bcac7419716cf7ccd3b8d4418e7419cb3c55715c392" },
                { "th", "a944d56e50e0951e843c8c10c03be963a8c8b1f5e10fe062948df1cb322b373f981e5ddebf08b80e6962f951a5d9627b6551147bfa5c918ba949ca246d903f53" },
                { "tl", "a62fe26381d99b0fe965092badd8ad00c05ee832453540c4133a3d9f5faa514984813741e2dad1f3ae56d8b7dba4c54f1297729b1bce82e2dd2d0be64ee7fe4d" },
                { "tr", "759c5d479b83cf811c97177a28f6a4d53c90f99ce41ae1b908f242bb435b05a7b535e7c31fb586f31af079f7a7779d1c116f99a37a72cb64eb2f64594fb330ce" },
                { "trs", "5cdb8c0ed829b036f404456c62b025b40e5437aab50334ff3393c507fcc5858e22787349147f4dd3de8d2d933da44dd87434c3881c355b71bfdb74baa6d64110" },
                { "uk", "ea45e4562d82862177006112a2a27dc4e70db7e0b477abe2c73aec9154c4836aa1780acb35fa5a617548a1246f9424cad1f7e5d61f62c98bd772f535b80b8469" },
                { "ur", "64a6cd607d1f84280c6257b0011e9d13ca522fb8089606c06ad02f7fd0b280c006e9f3efcdbf68ef4e820dd79d8eff2cacd1934a4238856e879be74c1346cdff" },
                { "uz", "ea1bda601b0cab81732d44135fef751d15d36b7a1bf8926fbcc2d99f7b5387ef4518555b94cc8026a89b80b2b0f59ffceec2145c6a9a05e9b7afb741e9d48290" },
                { "vi", "a2e0e83d67c2c90a97f983d193064fa018a8e234477d1c0f7f78a974cb14b6d07a4d38f551f0320d66a16ec9678d9aa9f1a022be58f10be8553393ba8a0aa2bc" },
                { "xh", "65d564461e5c2290cedda1d3fae7424487445a3ea4d84f8b0e5e2e727bb94fb0e8567776880ba38fc1ba9f50034e91821ed50ea73df6d6cd3fc16ddc2132aa4c" },
                { "zh-CN", "692262718603e08c300ff6b5de377b9a710f25a9a3b8355e72e4874279d1efe5a57f1ff150b9eed092e51ea015d7f2f9507e45e76f92eec5dbd8608b62dec065" },
                { "zh-TW", "c38f63e4cec9503aa03c38992bb3d0267de29217efa003a64477fc4d0381d60eeb41b5ef423667fe278f328b6343793cf8bf1977a7af3222eb4b0d57d3f26723" }
            };
        }


        /// <summary>
        /// Gets an enumerable collection of valid language codes.
        /// </summary>
        /// <returns>Returns an enumerable collection of valid language codes.</returns>
        public static IEnumerable<string> validLanguageCodes()
        {
            return knownChecksums32Bit().Keys;
        }


        /// <summary>
        /// Gets the currently known information about the software.
        /// </summary>
        /// <returns>Returns an AvailableSoftware instance with the known
        /// details about the software.</returns>
        public override AvailableSoftware knownInfo()
        {
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition( [0-9]{2}\\.[0-9]([a-z][0-9])?)? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox Developer Edition.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public static string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent;
            var client = HttpClientProvider.Provide();
            try
            {
                var task = client.GetStringAsync(url);
                task.Wait();
                htmlContent = task.Result;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                return null;
            }

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            var versions = new List<QuartetAurora>();
            var regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
            MatchCollection matches = regEx.Matches(htmlContent);
            foreach (Match match in matches)
            {
                if (match.Success)
                {
                    versions.Add(new QuartetAurora(match.Groups[1].Value));
                }
            } // foreach
            versions.Sort();
            if (versions.Count > 0)
            {
                return versions[versions.Count - 1].full();
            }
            else
                return null;
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
             * https://ftp.mozilla.org/pub/devedition/releases/60.0b9/SHA512SUMS
             * Common lines look like
             * "7d2caf5e18....2aa76f2  win64/en-GB/Firefox Setup 60.0b9.exe"
             */

            logger.Debug("Determining newest checksums of Firefox Developer Edition (" + languageCode + ")...");
            string sha512SumsContent;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                var client = HttpClientProvider.Provide();
                try
                {
                    var task = client.GetStringAsync(url);
                    task.Wait();
                    sha512SumsContent = task.Result;
                    if (newerVersion == currentVersion)
                    {
                        checksumsText = sha512SumsContent;
                    }
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer"
                        + " version of Firefox Developer Edition (" + languageCode + "): " + ex.Message);
                    return null;
                }
            } // else
            if (newerVersion == currentVersion)
            {
                if (cs64 == null || cs32 == null)
                {
                    fillChecksumDictionaries();
                }
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
            foreach (var bits in new string[] { "32", "64" })
            {
                // look for line with the correct data
                var reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value[..128]);
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private static void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value[..128]);
                    }
                }
            }
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
            logger.Info("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
                // fallback to known information
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
        /// language code for the Firefox Developer Edition version
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


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
