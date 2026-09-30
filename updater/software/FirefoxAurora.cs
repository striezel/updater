/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2026  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "158.0b2";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox Developer Edition software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/158.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f878e87409592fd3bc2a144f8d1217c3be2573eee2b530dcb41555d4fb6a5e2b3c75a3f32abae82b5e4ad5e6ccc265f0b7e08906117acc72897f7692be4598dd" },
                { "af", "fed453c1ad2632a8f449d7c435528026ba971e448bd9f18c3a0207ccdf8101429033870e3cd461329072e6c10a0298b54c9aceb8e9d5681321139cdb59b3eb80" },
                { "an", "773f35b1786b8883962a277a884d54cf071a759e378ed7f6a2485acd3e46ed46a4f3b856a9ea2d9688225b8b09498520f7e7446be844adb482d8a5f120e88057" },
                { "ar", "afcbf77c4207002c31cf66809c917ebcb8428dc18b03d1b1bce596b5b12fc1584f241d42080a00c5e33a5c3d7d47db791d015822b1e23d2a78a87b58924ca8f6" },
                { "ast", "2ab599f1e0e2e3e44a80260fb5d8c7f9788eeabae54b6d47b738228405ef2a0a2f23dcb076a3e6dfe670d6346c4f9fb374e7f72ff28dbc4b2646d40718e5c5bb" },
                { "az", "bc037f40bafbc156db2adc0dd402a88147ec5d75449f121284ac448fda404c7194b6fffdcc7265c2baf9943c7c9f3e3d3417afc5cb4fa9c63e76ef8da5519367" },
                { "be", "1e951727d0552016c6b480992c342ea8cf764fb411a34e3de8ec415410168f594c34f43c260346db0d072d89d96a65705fbfe2fb62041e3346d9d012751c9ab0" },
                { "bg", "e7df79fb1ae748cbb85cba2ab3d14851dbaa4d74b5822bc7bf5d09c7b89b979de6c27977e7ec3a74f08854062671aa25018ae0c173201324966674685f6097d9" },
                { "bn", "81319a33a891cb73f3b978a08b1a1e3db739e0b84d0a3249003f1b7e4d8975193ede6b412baca34dab86ba82f97958d12c21c3c75c3d230ee4eca19549f60197" },
                { "br", "f645ae4c763f384608617cc728af2ff6e1e2d7fb1a168f7d6b86c3ce0c392127ae6fb4e116a4bb8349964c1632f4aefaa8afe7ac8dd1e4e051aa7b98e87146a4" },
                { "bs", "7b16de0e7b9419cd7706e5d91c64b9d410ad2ffecd67bb80e4ecbb5349d2c02ec723205f77e3996d65ca0434634743f3708f853b5a59d10b8cf77bffa2088bd3" },
                { "ca", "e52288449f6d2512f59381351653a4ce9ab42513be895068b713fce581730ca01a454fbb5433469fd40a40312c81d7156eccfc88497f629cf380e8925063b857" },
                { "cak", "0742b889ad7ba13d92f378a42877c00e794136dde6c89238f586dd8f2c17d0ed006a7f6135782a94701fb6e5e64051a2aa803f773d7d977afa523e045247131c" },
                { "cs", "ae3e61a9ed99a0c8f7381d19c802de0152996c854b8fda0d0770a24c732f0a71683fed9a1733e1c4bc34075bb73be9f5e8c9cee752f4a8919f46e0476ac0d528" },
                { "cy", "8d07401ec7a612dab8e59f181ac751a735635b92fb9a860b133e71fb0aec90528f49c4fde62e105d2231dd5fb9491d59832e8118abaa2c20f08f20abec29eae1" },
                { "da", "b4edd2c637f5f6b95d50275f272ed8a240ce73f45f314e57bd3332953f05427bb8142baa67e875d3e5e4ffb58d7171c1cea473337d9a4a4741925ec25a4c4fea" },
                { "de", "478e7bf254baf9d380fc4fbfaa337b98fa4771d252207183e8b99c8c971701914130a09f5cf7f99109ed455a5b07d56203103be6131f2530c1020f1c6a55c663" },
                { "dsb", "c409a92e162a0f011f376fe95cc8d9fba10d1852b287fb3d2d965b14d75f46cb363e84beebf061bc183f7454a4f30a1f88924b81eb5d0b2e17d3c971782b3181" },
                { "el", "66789990ab840b80f1d0867f5172bcd40bd3fa812dadcedaaa3452edcb8d44baa2db6d87437e6eed33d6315262e9edbd7847e479a8468ff96b3cd84568feeeb3" },
                { "en-CA", "6304c729086d8b22131e785fba94b1ec5c1697cd35c0333c0ccabb1a02d78e75008cec8c22c56a93cd4b5fbd423fb5d74ee8e79a8487cdbd37329d8f8684ea51" },
                { "en-GB", "74969bd154ef5acee57b641409233f0ba2e6f948ba2defe71bae4de74fa5ff75cba5e7eb9edd1086cabbf70c67344e04fea2b9ecddf4b4c9427a484b1a812aa0" },
                { "en-US", "10d148cd1dd784597392fa17e31bee0af821cdafa66ac40b7bf227cd95e6d9fba434b9faf441ecababbe45344605446351180640b2819852554d490eb0aaf71c" },
                { "eo", "44d6b930abcb81d8a555724de0a0c3a4c4e881f976eff819cf5a9287e8dfb6be036c10892e95293a913d5f1da71889c0fae47caf65565ec6d66601fffbc4673d" },
                { "es-AR", "b1e8d092d5b33858ad2188656139ac3ecabd6a6b572793b827418e2c947c06bedb08100ba631adc48a05101092dd29201712fcc12fdf128ff8b032772c49ec75" },
                { "es-CL", "dc5250d047aa070b9e3c60e2b32fc700c4911dcf50a9d261a5e92923547b9fd9732e3423128e21987998df3c9332cdfeae57bbc9b69bd71d38dc631d9d3706ef" },
                { "es-ES", "f703c057580a9a6d3dc53d9c13e3402393be29a3e750fb1374eb612e687efe83e306f0db71669b5ba76765f7944c239b5d95105fa7832448f1b24ea899009295" },
                { "es-MX", "7e35370c56c9708c62ac219eb8559963c72c0ef4226eac7e81dfb59e942dc7fc8866acb4ed2591f302fbb9fd29f8221902e9a16f707b11aca19893740f434b47" },
                { "et", "28d502f9d020accf42ce7ea5c208ac344148ce2e969ba7e0ec58ad8da05abd88bb5efca75db7b3b5eb83d37127f21753df99ca1fef16a2077de0c1ab9d5ac144" },
                { "eu", "01c28755f69ec97c2e37e1c711e3cdeb4035c62daae5c40d677f25cddcb9a21309d2b408debf1ef114cbb9bebc30f7a57d1cf67a5938d568dd9af3d0bc743b34" },
                { "fa", "f3a5238aef521583610f77c7af1fe95f6adec7c05aa6bb1102e160a81829c1965939baa7c5534718fc59a19111724db6dad00cc80c4cb89d190dfed18e3812ae" },
                { "ff", "3a8abce3fd338186bc6610b3da999d05b2c1702762bc8c8f4bda72d36a6a3cb97407d4689de08ca4e56eb1c79ee3fe77aa18c813d1cbee1a3758cac165b4aa9b" },
                { "fi", "82cc7c33dbaffa2b745cb867e938407b03506dd54cc263200aca8847b750dd251882b3d859df452301be88298b50e019ecac0d5739e45058f77fba5c6fa56fcc" },
                { "fr", "23417329ccd37e451b4acdc5c0a28f91cc2a2fbb79403e61073e599069b4b9517ca7385c1493bc2de5882549423a457f9df082468a5f2c12f10f26608979b7a5" },
                { "fur", "10fe8e6ca2b09ccd986f0b6658ba2537790216530f6f83f77e54036e4158354f35efef98d2a51e0af361f1d69d86048770c4dcbcd576a8c8ea0b9e231f28561c" },
                { "fy-NL", "46b3d8257fed65a88b87e6c2f3331925df150e13cb1c58cfd7d1aecbdac380a0ab07a090326b67243796663672148ace7fccd426ac5e4ec0042daacf899bf167" },
                { "ga-IE", "c07ebeacd486291d69337a3ada6b769a7b199127f9f64e827db4e2198567aa36231c66438da0719354fe8fd7a6fc50db4789b3f06401e0646140bab1507eaf32" },
                { "gd", "0ce0e1982db1314cfe44dc95ac664aa2c8911ac4fd9ffb6cffc8426aa767b18975448069e621e43f8ec4df936959315b5d38867747ef5a5cb664a18791bdbfcb" },
                { "gl", "2ee1d4f12fbe27269618a437db9b2819e94baac3bb90b70e37270fdc170747d83e4aefb0e0df58aec36663c077601c2f3095422f584a5698d08025f1f28392ad" },
                { "gn", "7f06f1e4ea91e7cf31261ab6881d7a921be2cfc8294c4bb09452d59a84a5edd7b36c97adc5f92143b7ddde4288ba8ded9d5ac219cedff21d35340eceef1eeb1b" },
                { "gu-IN", "027e94b6a4f7f09850a682e896e777581dee16cfd49e72d233d95cc445a0a639b1fa59bf6ab77fad02f44638198d0ef518463cf76278ccd194206d4935638afc" },
                { "he", "17293d17fc9b72b4780f0bc50151659e4b4f69f1e276da7f0223e02d54fa239bc41784a27aa613048b484a26a3fa782200f3372e53c4b979ab75a174a1247ca8" },
                { "hi-IN", "6da2a0dc665cb282ff6d516b226828cf19df009a3174ffd8e473eac4506369d2ccc01ba8259c3b68b602db4ec3c1b512ea2b5a41fe9dbe180a37fba641ce1442" },
                { "hr", "059ed48cbaf0beecaff72f0d85215fdad0181e5b22aec2bb86e1e5db7ead921c67a9d781141f4f78ca1d15cb8e044dd3a917d7b4d1bdc1fdaf823db97738128b" },
                { "hsb", "d8e23940a70378e534ab21c85d6548f3e175302ebc59b1c4907feeabaa452956abc97444f5b475a75139cfeaf888fab759f7ca7a235714ac5a1cbfc256b5ae1f" },
                { "hu", "266e180b46f3f02a21e15d400c0bb6f67321bceaac2ce0866631d234877a1b0c29698d00bac5b3428328c04f63c78d94f87f71f4ebd689f4980a860f557f13e6" },
                { "hy-AM", "e8d3f09110ae45bf9b0a410a4a45cf77b48f5d88787c692f70d6b32b9bda4d2268e30b016b138a474912c06c6735adbf128ce4d0d71feb3948ae3827ef9b6574" },
                { "ia", "b0248f58f07baf352d0155f1699b72de7e601c7bc5407253461374b3631e8c516e135e1cb30e95fa5a2455e1945c29d627276676f4e7ba7c6b8c89e20ba7f96b" },
                { "id", "d891c718944545d1555f3f88ca9801023241518c2d3d06a4a66f40062d79580c5e8dc96f1700943f6eff90fe2b63da7183c4dd7d97ff16744b044cb14a9217d5" },
                { "is", "afaa548a0fc0f34082a4754dbbaf0b35c9bb6c2ff89cc65e65b1ef0d8321c8162e7ae7047272ec615589ae8eca56e540febad6206f0ceddfa0e939afa96a493f" },
                { "it", "43b1886a737a3eb9dd41db41fe2b4e7af0354967403a17ce062618e38dffbf398df4d3f37b92082cdb797b5b78ca154bed1fdee5550ba810ece6da7cef81f949" },
                { "ja", "c1b069179dca039bbb2dcb36cf623ca9733021da2428e7234cc034bbc554852cf281aafbae193a8764575ae7a8cbd7716353a4fb3c51055f9ae5cf53e9e41802" },
                { "ka", "38dbd6a6229d6a282965d78856c12058ba2f3a0682e825f6c6304562860c1bf080e6ca819fa74303bc43a69ee2cefff480e291b6dd343201c18dbfb6ed8f905d" },
                { "kab", "6beb79da462d360d0cf17b066d3af025068a3322aef20d9109ab7e910b1f86942c37a6f5fd646bf61e99ace3769254f3cc2b479912e57f9f886f40709a6b3f22" },
                { "kk", "d6d9fa8add7fdf7903fc00138db5be19d0ddb1907cfb127476e5b731e2e90873073e0e7803d1cbf7d0bb9d808425ac1e6ffc77ce5baffe608d07919be8749312" },
                { "km", "de9c777935b221b0152ef01b1c0f343e3eaadbf66771d6dcd7283fb6378eb554ad8da85ca6a1929c86ab2ecf8d2d35a357d80a748e7675aa2603ffca43770692" },
                { "kn", "4953c56369ca580620abe146849def602c03dcea40cd27d04b2e699f9d4d316fff7b15857f725f7181b8802ed0850e2285193bdd8cb4fed0669e6e95855ac7de" },
                { "ko", "ffa82224f2c38f211400408f880297f01db6a18895156c71d9583de81ec87ec49387ccfe271ea6858a67d0199a242086c14319de60a358c191e98ce21cbd8898" },
                { "lij", "59da9a4905a5f7adfdf2fdf188fdc56a6aca13826bfd7225198ad62d24318b64df9fd48bfbe10087069f0ffa26432c17e74ed124d604675ad7af31b69d277adf" },
                { "lt", "fdb1187e8705b465aa226fafbe573b0b4f7c1da1cccf3819e518379b5c1eadaeec0213bf6a6472b2c1f878fcbc5391a2b51ccc26a342242fa9a55da1769c4711" },
                { "lv", "6ccca4e202d4995c3c8b67ad1761ed7e130f426e23f47ab38b9ea71c58e6c64994e23df88a3fec2da0169a4f20b7a7d70bc146d52f73d9d69982b74d8a92102f" },
                { "mk", "50becf8a873a5c15c53b5b5b42b1634d8e9b3c7413456261d1fb0b20eae9663d2f391b2f96277fdecdd81cbc048fb7f6b2fe3863f4301813909accad137bdc25" },
                { "mr", "c8f176153385ee2597b1633193b78feca14a5c2fcf2897946f0e805651cc5bf102f924bd7250e2564820fed3141311bb36c0d3fbff3300b3bbdb7e82b2354f87" },
                { "ms", "9e7ec73644be0fe5a0a9a7b091267fec42d3ac1797a5ffa974889f756294eada89c87d0b5320262b70b93010227f956739383b5c629c6133e005f8eb764df449" },
                { "my", "5fb86610ecc0107cea2294688d0314d485918df8973fc2ca4173bea247b434bb962a5e17bc7706eab376274c866adc069cf0682396b3a6b4e44add26cc242755" },
                { "nb-NO", "4e351fe7523d9771da10cf0a23c1035c2d412dc8262a57e1d323e4ab1991336b0626157a8bd481b32220ebbd23f8ee5a0851b811a1df3d19d21bfb723b9af59e" },
                { "ne-NP", "643dfccd65571bd9290150b592ed1e89081fc3077bee14fff3c0cc5a7c13ad31cfaff3a9aedc6566efb98edff80478355db73e5a09848b78c22070cf14fbae73" },
                { "nl", "2f7c8b9ee5c1c49d34d0cdc132b74b99fef3949b6e8b8ea2c2090f072dd81a3aa79b1b95819504ca4c0db3cc3bf747d2b30008d46523b11204d65e52639e4c5d" },
                { "nn-NO", "bacb84c3a9e6bffe4e188ca7224a66f11a4cb9aa23c83bddcb13a09916531a2258b8f206992d901ce3d72e8d3714ebf608b20bd573cbabd88ee6d9085abe8f36" },
                { "oc", "c4b519f70254c8271f295e39f487b405ab5590cc0070e66855e0983cfcdd7adcc436ff9c0a01d07df4ae4c68843f0b31775840e1614a4a9763c08d23a08b85d4" },
                { "pa-IN", "a9355bdf45a0dce1ce232ad317ac25d87cd3a99ebdb3b887bb3058f67d0c293acb7c00d391e1dc9a29427f3e9e12b4001c4e34051f51f30a760fe6eb964e97b8" },
                { "pl", "3130f0a817b261a5b97dc2aad7bdab60bb2444389d3a436354c9e6aa02b9cd501f81508a321f8192124976faf1efd631e194f59b9d87f9e096a3ccf8571f6e14" },
                { "pt-BR", "cf0fe0a1c02da3e2f5d8afcb0ea43ce06040f84f8e759e74a63d29297a5bf502faad8c49dd8f1e9dd893f27c5d4551122f165bd7def9ba4052cd160fd42a79e3" },
                { "pt-PT", "a5ca07f125b4b080925f325959e559e3c19cce43dc96a549a629c7dc99bd124eb1c249911cc49092723a3c47fda1dd3c0ebbe0595c413a7a3eccbd4e87d74dd3" },
                { "rm", "4953ff5c5fa7571caf97ede01415eaefe031d7f2d5a5799aa41f17d513c129d5093f8b7093db87c045d48bca3888b13a15a616407d8b481d2b4c78ec19b2f6f4" },
                { "ro", "8c3e6a69b28c3e61bc0fdd7e2acaf5659be0e2800a9def97deae47ffda0c66f3cf209c478e7529667b8ea093d63907f318f46aa1e55296a7c68ae6512d1dd04f" },
                { "ru", "fe7783e891e08d66e463b125b394807200d219c3bf526f63a8399c6419a11a32a912700c380bd762e4e618353d87e4990dd7fc4ad6101f648e0b1f34390e2576" },
                { "sat", "e80587d83e32fd6b26e2d4890b50b6a2a131dd511c54d72b4e485b3725b34969130daa5b9bb8a78a3c31b327911d4eb2e7c146f035977a7aaf9493897de46ffa" },
                { "sc", "4a22d55bca512e43d63b8b15b0fa858f078da9c46e8dcef05579d6c708d1bd7407cdb8c285a4f6dff2c03214a5583ed3e82916224adf8dad1a8f8e437e54f6d2" },
                { "sco", "32466e1d555c49b474feb7b3d3b98ddcfab75f9a9e38927f9269551be5987dba394532d3ba5f015e213c1846f9f31f34a87d3945cf2d10d59fd043e4e45bdf4f" },
                { "si", "ba6a568d604669a6e6d7a06001924673f98be0d7ee1f8aea73c31695c034caf19464befe1c972045942ff0af37a995904dcaa0f572f44eff0991d404bfc49c8b" },
                { "sk", "934084e044eefe10f0eb7d64854ae20fb2b7b2caaf3f8ac8cee0a607894106498a252a96795bd35eacbf6e1b036677dab65713b182241cf430aafcfb8fe8b5b6" },
                { "skr", "b27c4a20f75146dea5836060dc0ebfedf9ade0ebb00419a29cf917f6e7373537a1f246734720af8414269841bf975ae95f23656f1a08dd1c692121e2cbba27c3" },
                { "sl", "82c876127b20ca23b03b7bde30a6a906d2ec83808bef1b74c66b1ec06f86b3431ba03dd2f913673b03a1a4747b4320afc3ab832d0bc42542312988fa9e0058b8" },
                { "son", "b270593ce8739f653af05f3d4771cd464f867b1ea8641062102021d097ed435ac8ad13c207875bc0fddef167c6adf2a35764629c36f2087a75ef2b23bafebc84" },
                { "sq", "d555196349ea65dead3f342287109e6492986f3cb84c73f04033af34d6c1b92e65a9b86af7784796705a892f9f0130a291931d8fa9034f4576f6b5b54c118ed5" },
                { "sr", "ecbffe6a51066e92573f4aef0794a4c26c0b9553ac4c5e1c6690c8fc71bba7169d5b906508c8e44b82be6a82c7ef400fba7e6f24ba52d242c3fdb5abb7a6eed2" },
                { "sv-SE", "4857fe1a8348375cf6eaa7a66aa61c6d200ece32df6e66df979278647be1746c5777a56e10b519aca24767c743dc84607506e5d07dc63e2f2cad6b1a6720eb9a" },
                { "szl", "4ba232d6edd3cfc65065cf2dd2265858dab7afbc28885b9004bf1aad10084a7c87ffa9d86723739bbf480f6a354e3be5941fea372978d073c5a222c751beecf5" },
                { "ta", "3c12af0704fd80d79af92a228f1663ccc402728a0f284666d37463b41d20cf192f13e7ae8153b7223bba5efce9113144d9e7962adfd9bc1f51d56147347ceaf8" },
                { "te", "5c67a81dbeb7130e1c2eed802f2e759c01901c6cfb764900f1c603372c923c89470a543734b67fcfe79743186b37c1c10f861fb26347c5619a865ce33121ef60" },
                { "tg", "d139bea44a2bdf188ab9deb9705346b2d121341cbac3fd59693adc50152016bad9e9d8a2343c1a9c7862acdd03ca148ad3341d6aebe8a9a5ba853085f70e37c2" },
                { "th", "a6a3b78cf6821e1a8748a85e6aa33f41747dcd6377c42b5a82a24cc14ecd3e0e3d8acf73d83b489765f0feb503e6e008abf2b8f58f0cf0f27f7d9be63b46f8a1" },
                { "tl", "c4fffe3aed2b80bf2b4eb04314fd69d0dc08c0aaa94095a95d2b82e5917df46e34dae7f39c0f4dcd21c994eb80d94c71f0c3bd14061f5c453d652b641fc9b2a2" },
                { "tr", "bc071f560cc2783b2880624efc13ca1f16cbd64a37b9d83e13361a91ad9412d8a10edef5f59640173387cebd6624ce816d7e81832b1e2101b08b7d1478c8ec76" },
                { "trs", "f0024d45c0da867586bd4cad68730cc3aefa707e131afa8030d28cd1692fd22835d3cdb8b0bd1563de22d2dc28fa2e8eb5053ffad1a2d0c6fb09da5f821fed5a" },
                { "uk", "010a91ec19c7fe56e3f43dd006e43607439b7e75a46bf912b0030f564af37ec5563376a308c23aac52785482e5e8406b7ba24abcf9c9b36cc4dca448da2ef820" },
                { "ur", "669cadad17de0e780de4589306111058b2d5c37f8abcd4128283ba52de5d76dac4f5c5d638cb6b5cde6b2abe01fef286dce82ffde5a02ecd131bdfc16b4a47f1" },
                { "uz", "f788033ed3f6fd49dd1f774670e90cc4aa393f0a16a98c639039557fcd1940386ff5fd6e500b505ab28e94283f0288b7bf176ae6f70b5ac1e5915e5da0e95d36" },
                { "vi", "231ed58f5cdaa31e733c6c8f6a4553b4e34401736db50e9fdfad167f0f1ddea571bbe63b521cc1b51e336ab4f986d60b60497e06d446aba453eea9ba3f4c3a5f" },
                { "xh", "5321cac058574c3a5702616cde87eea485daf43dd30f9f307190c6f3850e2cec0b79e718f293b7f5c2bc1bb7269d6cc61f39b972d1a397e92857f13b75b6c562" },
                { "zh-CN", "5ed9f82ab3daccd070bfe2ae14c0a93f188ef85898e8fcd3f51528e47310f6dd926ca1b06a3ea3998d60159a2e2b15bf6c0c5bc1e42670552093c2cab5a4f724" },
                { "zh-TW", "83ac599b4cfbd3c5612c9b62211f0dc5b813182f83c5713cd4ad4feacc4d8e4c9aae2337a353adebfd93474029e323a958010a14c883fcc4edb33b7e9319872e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/158.0b2/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2fba9999884c1c23400a02e6feaab0e438c7877c1b4856e41f46fd93fb86cd71d20a980761479c3fb0705b9978b9b1ef8f70c0052fac81bb818c1c7843195082" },
                { "af", "340f895544a92f79cb4e2d527ac14b967f45168d4831a3eaaf2f3ffa373fb21f4b642af789891746fc43adbe16a5dc0117b5c5877ac866d69811ab679f038719" },
                { "an", "8d12698859d0c2064e38149bacbd47314da9227c2aeefa0b3e62599f61a939ab352bf13559397d27df4718a6fe1cade955fcda980c48541aa8237cbeb164fc1e" },
                { "ar", "df6ff632eb89c552748e64a923e2ebf88562cf718d0b49806f043a110c67ac60a24321c1ae06eeccdab7f75518ad800d4d8da1976f97b4228f73cae3e14d2881" },
                { "ast", "5bc1fdec5b7473611f9a7940a582d0158cbab5999a22746af8bd05e0ed2cb68c445c35f499c6d65de43bdf88e39dc1c6480401d8ce6654233f284e69222f2ee1" },
                { "az", "a30ef862f954fd5fd052c4375be7076dcbbf463699cc6bef246f6ddffe43ebbc4fba196124fd909d633432658a37d88539de21434351d6a2bab3c7b2488176e8" },
                { "be", "65ac267607fe264130faaf4376a7033a032e4c7bc7f4e0877a7853cdc2d7f87ad61017390170c93dc52951992d937263d64bc74feedcfd5ec83637a87dc7fbe8" },
                { "bg", "fd2c17ed5301ef4fa600940eab4bf5435365d7b233c201e6aacb9e078ac9d15c8bce37a0b168fa05ea919e89af9d7d79b72f01513a219294d5eb204108de19c7" },
                { "bn", "90e217cca801e0eb4782ecc8f1389fd271d2ba0b43efee1d0a891f34f85a3157fd516e835777d03f4c9543b688a9c5417480bece9a3a78d1a756485b9018fb70" },
                { "br", "86059d66015e9b5e23c384a808e8dbebc0475be0161e0151d7290200800ee2b4034caed663fe5382bdaad9f1cb562fa50d30ff13c50c85d0bb9bacb2a72f53f3" },
                { "bs", "911d3b19e0d943ed076a58d8d6c5c3133b7149fdf83fa573577dcd222f537fc2848527fd2b621cf3800b1528ef1b9f8eb9d9273f8b6cfa8ede1511c6039e05b5" },
                { "ca", "9b42473d73b299b2a652ae523b3b204ebfa04682b9027924538321ffdf0d392a3505249c27b3e927b6145a8d0a4f660574660b37896052cd5c1fdee2db4b4a34" },
                { "cak", "5900eedee5ed669ee7567c1c8a2247dd314aba6ebff7716f5cdba939be29d8cfcdc7eb469144308ec1364abbfa77b483d3ea0c7ced604ade94d65feb7e003957" },
                { "cs", "1aeed2b3e495a0f48dc61fd165487b952e710a12a23ab5770f8bdbc3a3d06f5abcf4ba2d20f21f36275239bf525a143061af9cfc709b09e0ea7fd4e6f11cec84" },
                { "cy", "4fc1d6500918c064d91a20f484912ecbac38cceebf351869a62330bdd90e1c2ba6ba03e4a511d28058a482e9ca2a3c13e795f6f7807090a828a6afb1ef81c159" },
                { "da", "ec91107bcc112661838b71c39e02b436a52e1cce746c436f0cb67c37ffbcd20144428789a6366a86305fe063aa966a98a70ae550191a44945f1713e7e73ff2c6" },
                { "de", "eb8eee649ccdffaa076127ce47f3184e51b61c25df153ca168aa268a160eef33feefd224a52df33045e84a0955257dae9336dbb6a49b5458831ae19b6199328c" },
                { "dsb", "1b8fe0e32a6446a457a30bd8d7bfbbb39fa6e6c93d7a21cf0001ec5ca6957acff9efb4f7d9abbbb88cceb26058a68a53558093f113182d6aae21030f8250c316" },
                { "el", "1cdb7193a39fccaef76771f55032ecad808d2b06bfc5f5d25101f2fa19d09e4b0748ab35b6d2c628b09e55a548f3c96747962d44a2167a190c24074715c5e668" },
                { "en-CA", "f7f3ae9c98d6d8080cf2addcc2e1f694d556270b9aadef017b0524d41d1c04482d663a06195f5e8beb1fcbda801489eebc5db52aad37a951c2b9c21c08b6d883" },
                { "en-GB", "25c009f17fca33fd75ad106ceb661b9dc639fffc83321b5208c36231c32321aff21256902d8af906b4025ae2c8f3b95edf70c2bb1422951e1ccbff5afeb342cc" },
                { "en-US", "d6e96905f925f6acbc8faf92487025a6d8c4888941f61e4ec268d3f272a6d9a3fcd862b33d37fd3a1fa0a90d89a7430de16d3afd3141565897bfb13b4a46dc94" },
                { "eo", "1ce8f3d0300cadc9e1599d083738c0ae804330e66cba3a4c67cd29ef421e7b817bcdad72447ce243762996b2e31edb884db6e035fdf4a8c1da3cb07d35511cb6" },
                { "es-AR", "bf2a3acf0a07dde8d26c8a6c11d6576e1df45f22306b1042480a3a70460ccb241ff5044bf00ce6fefeb3d85f0c98142739d41dd1f7891cad5f3e072840c006c9" },
                { "es-CL", "1d3640fc145723c7755413b750464311f41b8105bca0849c96be289cf9fb0da1dcb3fc6be21dbecb6fae10b02866efdfb35b4472da7dd8575cc4f23e7ecb9cea" },
                { "es-ES", "e5bb56d592ca9a10c4e9b0d5f16ad891f328f66ae181ee1071aae0713f367072eba5db156f12bdacfa9fba46eae4f345cbbd5c666526850bbd056ce86ed35b56" },
                { "es-MX", "05527fe2c2571884b52a29ff60e140208b3b92ab0687fd332022c54e59a7549d6b8fa1b56d4f9b20a9c97e03cb38ff69e627506039783d8dc6ed2e4c65833029" },
                { "et", "9837f5a3813905bda4e464ccd20636e10b0db1d288bf5cff6d09e3dadb707a9efa4e5742e11cd86f7e4be328682c9165bef1a0b7bebab27202b4bba596ec256f" },
                { "eu", "a055b5a7b057ae6d7526f46ea40bd76ed6e3a94aa2639918df4cf9fefee08356b5dc03d1c75ea87219014cf6f5f09371f39e16813254a24e87ea43969816aec2" },
                { "fa", "f8e7bc02b45904c96b176cc802ebf51dd9364096618b5a7efb9a711c0d1cf368fcdd9f5108cde5f1c2cadf1efc008bedc3604291908a1678f825ec69a8213d5a" },
                { "ff", "d157fad70d587418cf8fb1b4c8bfa4c7cbfc38a3deb5c533f0acae38e5b537e94de57be6ff5d731397ae137a99733abf54f7577f3deb5b3e2e134b31eb776650" },
                { "fi", "32fbd6e1036c72af276fc1edef7e1cc501967f0e49116eb105b79816aef5abbb36325d8abfec1c1e6743dcf2f4efde12f6079345fe55111806ef771c61dd1482" },
                { "fr", "c2df4156b8ca8356d4b9abf566c72efb5f66c0a1fcf24bac4a2da655d1fcc046014bf13f59b7162049b943bd1dbf9fe6aced2aee4d718c9942e3a8be7b8c0c8b" },
                { "fur", "8c8ec86c38776029ffe6a4e050da2f0337dbab35dcb62fbb8b7b061bc87d409057b5ce7e46ec96574bd75237cdf492596375c448e432ccd9bd8000a6ab0305d2" },
                { "fy-NL", "4a3c205ac9ac12946392d08b7b10943aec36ad28967d6c3273c1938ed647c0777387b7897e011da4913a451973d5e0cf21bc885318012fd04f1bf50ff174762f" },
                { "ga-IE", "e9e99aa1b980b02a1a87314c4459d1de53871c340a3fc14690ce61f01c23b4a1fe3314dbc0589c79982deb353ec141a21a3b51222f1eb1074e6ce8d8549b0a75" },
                { "gd", "235f1ba78bc5e1557c982d58fe6b563ec91bc2618c0ec468d427dacd828397a9426f4cc417ff72d88e2cec5de611adaf7a24d76071f72fcf9dd05d0fcd7e9d29" },
                { "gl", "c832a2e9a44469c153dcdb48828934ef106506b3356e4642b06ea522da88581c726447257fbdecccf75b3fae4d09fa2693314d18f7802b4393ad6e81d145febf" },
                { "gn", "daafad81629ece71cdbd75d250e63dd2a2161400d29715eee4e5c098b033a177f7440c83bd29519b82f499019ed9d0b0dba354e5123f8e1c218e0e855ce41b71" },
                { "gu-IN", "b98cc278ac003f5694fb9250cd9c06d5d15ae17c59b5d9ec5bbb6c1a3dace42504164cfc97f250b77ccb17a8d516881e566812d302301137966d36d10961c2e6" },
                { "he", "e3f242378f9f59da8b31ae6607b23c647fdaa6f5177db7f8d5499c7605ea4fe2c22f048cbb12cc923ccf68dfd9091c1174abc09b51409a28007f97bdbc31f829" },
                { "hi-IN", "b6a02c0f9da7289c8a86972a465dcd5651a9d0836dd5a823d8814e9c3d7251389069bad0803f3ac1708806297bad77602c5b4049f7db53f61b876eb64e56d9e6" },
                { "hr", "6369c2c311ac9b338706a84ba63363fa6301d94a0a738ee1ff68013caeb016132da2af1fa70c76c1456d7414e67ad8d764b6375d7933b90df05f0cee31244b58" },
                { "hsb", "073694c32ca46709d0f13fb8ad8532327278d79701eb4b6db4afafd5a10c856e7802f789b06dba363a0f20039154753b36f9d81da46ef16c984199e7d40433df" },
                { "hu", "731242f3af5f430120183287e723f3909eabadae3d12e8330f03bd1628e346334bdb51aa6a572f17c8ea7576e013b8075e864e7b07bdf046e9f00a2cde752a65" },
                { "hy-AM", "caa5d9e279a26e647264415a872dbb7ada31cef493017e8baa0adbb9a61588f0db1e2bd7546dd211823a945c87bb867d5fab0062bff0b42e8bac3a35b1e783fe" },
                { "ia", "5d12e61b5e25fb5cbb47146356d27d71e5013a5e5f2d541cff85810410183ef349f81a405082f18728a83ca544fa290c54165cb8e72d1718e9c5522fb13a1ed9" },
                { "id", "a79efaaa9096367e4bdf2752fc94412f6dc9c54e294a17fa2ce4950971b8b0c3e1fb1ba6fd2ab880a39f2303f5d830fc2e29db7f525b78495cf96a123d919bfc" },
                { "is", "a02e1be029b5a1e1f2ade4fa9b3c9ec6354e6a2851bd42c0d0a320141da7b544fdb9d93ebb7ddbf534c0d95fcc645c709e3f9f162a1ab11a8c5f99f3f9c8dc90" },
                { "it", "e31b6e236712ef270895680d0ffdcf6abf410d62b5854c2655d5c8ea8ebea84956100e4a583c27ccb5143965e118e281d8b204a107f8ae16cf40b7694cedcb78" },
                { "ja", "b3b8ea34453325cb4faf61d8a4f5853f60e3bb4c6a6ed2f9fefea912a4346b900d6d858f68c35c346a3c8256f468eee4aa02f4f254611324f036112af9681527" },
                { "ka", "e0aa454e873b2bc5527b090cd1d989743d453af93db543344b30361bd967a6f8214cf37e89ccfaad2a55e440b6e9339b1199f6163c0900417491440f626156ad" },
                { "kab", "ace7a1c30c550585ded984341479ca94350d0794dfda8466c439aacf9f6769b774463be2ec7fdef7f82e2e2eddfe6a30965bae99f58f0ade107076c2db1c3871" },
                { "kk", "aa749609f0153959713e2f6d1d313576bb54eec530451901756c7d426b90907d2e9a94109c2047cb8d6fec590340c2cf2bf8586a0f10262c3c3c30dcb79f38b5" },
                { "km", "9e7a89e5042c082eb59832aea94db21d1c0b03034eeff1267c359ee6d9d9d658cdc24086ff3e8833b706ad5e9bd0b33cda124fefe070020858c60485a9c7c9e0" },
                { "kn", "9f94ddc7c1601d4b09f702c4e5ec0be94c92c26036f91bfaf5f4cf76483d9be3b6329fbece5e5044fe9d8e1767372a65d2902c243d6daaf28f07d7eed236d0b0" },
                { "ko", "fb0941717c2a0d26c2a44cdf024d874994bb4c7dac1c942ed1531f05a91e8dd6eb9b562ab3402befc2a71772813db38ffcd6e9f585a44c6297281bfa1588635c" },
                { "lij", "38d6fda583136b76ae57ef5363a2e43b9d7c6da771452eb97bc276833034129bea05a2366621af9cf0687731644479ebab63a6fbd9703dbd8fba00b7a66f91b2" },
                { "lt", "6882cb3ca8d7e3b518dc853c1e5937ab4a7ee8dcd0269ccfd996391480b624fba90e689157aa16aea1064ba4afd1b3badb4b3383641023e9faa2330672e7f6dd" },
                { "lv", "1a6c701dce3791deaa704cf955a9b9fcdc03a9c72dddf5fac35809d91707d86af4334046b37a9cc7ae4cd71ab5a5ebaa5ccbee69feb08a9ce61f46f4aefca67b" },
                { "mk", "96fb97420eea9920be292f81e2397a12910146f9ceb6759d092dd606d4290f9cb6e16b9f08a658d79f63ccc8f49bc6a664bfc7e7594d89f18fdf419add6a3697" },
                { "mr", "90ba685063762060ea56d9e3636494ea87ab7130a04d70dfc6d4bd2cd4c043e418070eafa3ea201dcca00e96103532a2611e85e7697c92e06f1f8db1cf455e22" },
                { "ms", "e80d473172f116e60e5d536f02562883fbd98618a21f183134d8d932ec2e262168b8eaf1c1bf497c9d5809f0f3e81801223c447212453251a113d18b8806aaac" },
                { "my", "9263e94af830078936ac947ab26f538a48661f7ed6bf4ec181874533d64ac89265645b6d30b40dae7bfc906506f3ab1e39693470d98f164cf64781c9ccd67bb0" },
                { "nb-NO", "69d20e80e83a4889dd155f834ecd55c0e3ef4b2a205a4deefda65d3c24f35cca8debb77f95bb052dd33b9b3d6aeb093240a85f9b32acf761c1deba458fcec1ff" },
                { "ne-NP", "1ef206ea1c69deb4e8e3593cdef9c637335526f6f3cc9e2eed34ce386604e08a4822b5338b92cfb81201deb0ea3bffd462821b5844960cda9b60ed827142c67e" },
                { "nl", "be1aaeb1a2dcb6a219d9b1fc1a36c1d4245164c6273025f45a63daef91e3f0472adc87e5af8c237a77d4157e599b3bde0722775826d6f17e8c926b3ee11c8f6e" },
                { "nn-NO", "e6c3c5dbd2d1baa18899036ad4b123594d79ad14ce2e210cfb56791ecf51fbf2022cd1d6bfee6913adc5d28420dbfcc60017693999a751b83a6bed20162f546f" },
                { "oc", "43cc97a7c40dfc2228e13e47e684d8dcb57ebc3f3a450a64e9b1e16b640a6b940e5f08be35873d12b3c67c6f938a7add075c7a5a98baa454d0ceb6e874248e80" },
                { "pa-IN", "9290d72aa99685b55b6b6b63b76b86a4fd4e5ea3a3494bfe9960488c618a629c3087a37639f19e9fa20bb412f5eb0ed3e7ad7fcb3d287c149e8dfcca17613e85" },
                { "pl", "6875e24ce37be3d5f364d468edaec5eaddf2a76a55c81c2f78c61ec27419faf46f9709727161cc0a0841f1dd27bca122f19d784ec9ce1bff4101ff8146b8b4cb" },
                { "pt-BR", "8950afab60a06141f4f983b23fbda78078737ec70f25ea4dbd42e4f0846f2b8c9a3d81d484050a8465bd99d4e0eb43dc15f8c5aad6a39336fb8bec7452bb88ec" },
                { "pt-PT", "3c9037ec99b8911d96458445f1eb9438d499f311df3900bd9a6d604d219163df3d7ba6d948c346d0ba18f8960f78375342f2a9d485e9d69572cbfaf8aefdf89f" },
                { "rm", "88314b6d55c4822d23b5090a1c72a1c65340006191328be4fb85320fdb941d5936396f579cd1d054789ff357f5fdb7e515118c299bb108cb301323a347acb1d6" },
                { "ro", "b2e553c99c254dc56961cb1fe941152409bb776376088b898c9ddd680fc39d813487187ec66a743740781ad88f7931514c15dd51811128e6ff3d5015c3e3b2b0" },
                { "ru", "226a1781715ed445de23874ffec7ea70a7e2e3a1563ba6aa465b18e5b2d6196b3c61b10442148e858d022c725bac1dfe8dc8bf83e0ebf2dafafc6cbac50e8e4d" },
                { "sat", "53799d94bb100fda133e04564ff8785dd843dee89c3a448af3e54176da21eed472be56a6edf288cba11ccebfebdc922a6f0382c606b3709c38f77cbd0f5ca361" },
                { "sc", "29ba9174301941d879c8c272c8d74e1a5481fa424dcdb52f61a9fdc3f138200a92bc4d7c8745cd939a12a09b387085be0acf684fb7d4c1a8fb1f56c90414ea13" },
                { "sco", "1b02001e1e44753afde122ccd3a5c4f7e067171eb4a5d64fd547f50f4e376b1c85fce18ff45668e3be9ab389bef53a9dc30e2554928b635a9994c02d10df7bc5" },
                { "si", "d5f94ed6c5e5bf0ee8bdc82c3467410f778435431efcc50cf5ee2b9c7ee49af93c8a47998cfa85ada3860758f058b1b069e0ed73082c62feb1a535fbe384a527" },
                { "sk", "092ffeb50f03582aaf2c8482256315c119135f1e9139843caf7e9c8c106d418c64005cce68954ffa105ca482b113964e4d4332033bc0f0d6badbc5b909b62c68" },
                { "skr", "d8e1eb64387660b78dd9444fc7c314d3ff4e38e5794898ab3f2086d6a860c3f2d71267e8bf344025e9c71a66f661e6a91285cf13e7ecadb5b1c3d53606ea4455" },
                { "sl", "b1981e24232c76ec057da2bb72cb7d76a3618222c35c8ed97b274d186bd48144e3e88469e63196d9271e0b6e2182fed2ccd9af434932d905952ab2af66f95f94" },
                { "son", "4da62123bebc0d6b90569ea523158e3dff7410518c302bd436768f0110fa46ebe98667d7737cc8161668863f6744d795702d9ef3ea42675c27bfcb8b9f701933" },
                { "sq", "48490b7d0b61249d18cf6c7ad07107d9b4e2858de3fec289e10ec398124af7b84a384494793ee55d75edbd33a52ebe35af98eda7490bbfad89d5567415ffc58f" },
                { "sr", "0693d9bc88bdc0a53264b9757f981875226b2bd4ed7679d49a6331c76c0e5c244b3720e1f4e965c2ae3146d9e8fdd1febc1c6c946c0793e45621b86ba527918f" },
                { "sv-SE", "3104292b97c460dedb5e41871205d952cc9713779a5f25571e9345f5c12d35c129c9d78b5824da7bae0755f6119be30b07db025c0333714e13bf36c268f902a1" },
                { "szl", "73ac11026d469e38dc1d5391616a094d70c6f4f4a74332a9773e35b9bb644bda1e0b70953ec14cf19a35aa90a22ed8b0a6f3bd79794c478f2b25347d0feeec54" },
                { "ta", "6309313ab52ddc39c163da2e6eecb866c741867855b1e68b596d560bd242d7a58029ba674295c511c12ed573d43d78ff1c7766cb33eb46ac692d223ac2a63e4e" },
                { "te", "4d29dcefbc9869adb35dba9cc5aa4a8b7a7d750a790fc92e4168534206363c670f6ad7ba4f7dc6937ad820a4495a5ce77d747bed91ee70dcab153114635b7647" },
                { "tg", "6b25063db340c6a28b29a39353c1ab0581978c3b0a6db868d1a846d2a568b70b312752d30b14a41860f08d9ad7cb5340a8d288fa1093db5a34f722bfe5f511a1" },
                { "th", "c671d7de2d8516a161546db4ecf512379a32c9e1aabd4a849b17bbfa65fa9c85702e6b70bfe4b1a675bbc35c28138e5daaf6c792f95565c66836f177fd449bea" },
                { "tl", "8899a818bdd55ffff6418f1bd664593b341997c356e4b122c931ea5e12e7e59b84face8f5396dfd5cda5c2151ca14f3b79bcfaf423ce393f783e50cb5b8c4af1" },
                { "tr", "27ce0701555bdbb098474b3712407424d7b3fef36c02d74de4f5143b4db2c0b3a47e2be908104eed6bee7e6995dc4bf74c5f000af8dc2d032472acd8c15f3d27" },
                { "trs", "e3fec800ae87896a04e33002ce187ae69a402d8d4660630ca26b32a1262e5d17e115a68b32905beb6eba9d0b753cf685154d4667cbdeccb27baad7a656cf5b01" },
                { "uk", "079342eaeed861ee9773cdf8128f155f01edc1bd3262990111c723a9707b8f0e69ab3a4d66faa3398258d48ea6685fba5868dfadc5c6080804fdd72b86a0699a" },
                { "ur", "eb7ad814bc01fb8652d785ebf655b66a8f8916a378cd4f1acef6922dedd6d018e4983912d90fcc2136921888e0cb4d64bedba6b82a7c7a90e1a94b2df7bd8bd7" },
                { "uz", "0c3a1b0b803b643f93fdf3f52875d96f2203c23b65569f3a51f62ffc168ea77767eeefa9181b5513e453f2bf09103f67917c8a8fb07a960ba8f89f97a7cd40f0" },
                { "vi", "f2da403c69f7830d46eb4190bcba87288e42438f5622d2bd8f7bb444bbacea8d3da0ef7765f900850f473e1f6cbd8a1722501c23f10778169e0b6c186cffd908" },
                { "xh", "601c0c6e7bcf129dd8d4ed36e1fc186b747d4811971e66b36bc1ed7eda355b3b40b1b7996b551bf895604401a8a32c1dc7365fe4ab4c3572480c608ac8fca390" },
                { "zh-CN", "47474936a12b3f7311f7a177d1b397e8f3709246d393e62695351c1ab9e47a9d03e34636c4dc017afb5da798b58c580aa8726b91f65ffb65c336828d1b1cead9" },
                { "zh-TW", "bd85b0e5a3ddab2dfa86fdb264c04f4e1ca562790679776652c503d3b9e4cf2eb6a020b1815bc5d6813484b9d964fc0f095a160757d87a70a2d9e9571ec57271" }
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
                // 32-bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-aurora", "firefox-aurora-" + languageCode.ToLower()];
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
                return versions[^1].full();
            }
            else
                return null;
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
                if (cs64 != null && cs32 != null
                    && cs32.TryGetValue(languageCode, out string hash32)
                    && cs64.TryGetValue(languageCode, out string hash64))
                {
                    return [hash32, hash64];
                }
            }
            var sums = new List<string>(2);
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
            return [.. sums];
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
                    // look for lines with language code and version for 32-bit
                    var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = [];
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value[136..].Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value[..128]);
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64-bit
                    var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = [];
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
        /// Determines whether the method searchForNewer() is implemented.
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
            return [];
        }


        /// <summary>
        /// language code for the Firefox Developer Edition version
        /// </summary>
        private readonly string languageCode;


        /// <summary>
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32-bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64-bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
