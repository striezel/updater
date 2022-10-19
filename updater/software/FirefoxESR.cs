/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


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
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
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
            // https://ftp.mozilla.org/pub/firefox/releases/102.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "4f6f5bbc6b8fcad26eb1bc58393bee2c112dddbd270d02c1f3e0c87da958950dc992a7964877a18a252a48060225f08f528c2f4ce20086694102d9daccb2ca1f" },
                { "af", "899687d15663a0d98e91692574d91a80a83d1f7ebd783a917dd2377db54f595af696115d84efe0ee611e5d7b54818cf93bd3edef63f33845a543e06b43f96e4d" },
                { "an", "c9d4267805c8d0be604119a4ef77b4240acfe4d558c38ecee36509bb43c722c72e44f25c45cdf86451c67277118c50ee365fd338a19beb2565f89462d46062a9" },
                { "ar", "9f2813d56badaf8095d32d31825079a454df14f8dfef0e6b178327a7ffcf1a7585fec91bc5f6a4b16adb4fdad5df27cca71414dd077ae6f02653c727bdee2f43" },
                { "ast", "73330dc2a5e19d94cff7ba1baaa904336425b0ed882a9ba1c81b633118af89695e728b01f8c38ccce3735bed290ab759c6a21310d14f5b3042148864fa50974f" },
                { "az", "ffc99ec83fc8c587e157d341a9564715f14066977f88f20640ada6e7c550f5eeb01431a5c3ffd2d7ea0b6d1cbdba88cf394b495aa2d4f184f25403e9c4278dc0" },
                { "be", "bae01b7652965ec00a7c8a286d084f179bb2d9c9e1a2f02085bc7c47f21423060863bff4b2ae11627be8fd48dfa1c13832fd0055f881fcb84be05d59820cda4a" },
                { "bg", "a2bb451ab0803c7d977d3a8496d293f4de03d0710c83506ff430d0783a6c2044840a443a38a1fdb68d7d61329cccfe936c0fd6b5656d6ff5a8c85df33b5e50a1" },
                { "bn", "831e88dc36f0a97a78d6abf589109576a714ad8056d3235d3b044f53f07392ef1b5e4f151bb84e32239b5a84e77175becca91d6c09d336497b4b062777b41e7d" },
                { "br", "a61d759451974f3dd501d03d56c59475153bba56fd1a213af1bd123eef0625ce7825c6e8b1f2206825b6499cb54fbfbad8eacd4d2125dad832381ae52c60b62c" },
                { "bs", "28dd09910ac7b9b8b36899ceca8c565608e9207956982f2feecaf8b1d28375cba7329ddf41996d242d3d06aed0ead73848a5123cd33b2f4e09cdc29a372f35fb" },
                { "ca", "a8ba9d09eb1dc06ea726a59eed23361a485caa33d87e6c9f904f65c7a27c7761c3de7fc8fd3d81597a006e2838594436219ce58bcc394bd3659b2710791b6081" },
                { "cak", "98bbc7122c32644942bbc047afb1c0555913427ba0133ad46f4bfb806e6ca55659eec026a0fe71e8e965d350b2bf71fe49cb88c0f38a1b4ba17d93b4411c6cc2" },
                { "cs", "03ae72e91a8a84ac201476e779c02ca4c088285a38cb0ea6229b54dc4f7100887f174c375aca63669e426afe20dc1c69b8dcdde2bfec21bff59fa10247e33ef8" },
                { "cy", "b2c2ac7cf193b404b81425103358e24f455aba2f89351f84f98c3dd1ba99c668ef506cdf0314a49c2bacb5897fa867f8a00563bbccba9b89170145381f8dd8a8" },
                { "da", "f8759ec19cce69482de863dd15a4b4457c1d684740d6d651496bd3ecae93ec32f0c93e0b2eedc2500b111f85911fa114aa0bc18a07449c01f3ddd5bec4affc1b" },
                { "de", "3bb2e6d72da3d9d00c88ba84d231bb61fc96ecb78a226e90b1e011e56b99effd1c605df85fbea50d8af6355fd379ae8654e095a969f10592ad7172157625bfe6" },
                { "dsb", "f7025720570598922af0f04ea86108498dbcc6a7736fde6ea2b8335f413ba49cef691f5350104d13b014bd13a7f2e20df48c18c27b63c1f5c694397fb2a63942" },
                { "el", "f14063049ea479197ea12999978fb09be258109c0f376a06908d7c39c4d8acc7079519f0e5dad3ce789ff242c7f9298f3bd7b7f4cce134c3d391d38655de0dd0" },
                { "en-CA", "32d32da7c4713a4823ba14af21d33f4f754593f61999fbed5de61fc3ec6951d505339c5c27c160c1ad758bbb315455bb0d19a7f3b9303ebffe0dd1d0c545eab6" },
                { "en-GB", "97f2ec84ac50e788f234ad4eb56dc8c94e5bad48a8036eec0bf97001a8eeaa7090213690004a8fa3ab361c720adaa60a710cbcad5e0680e63aded5c4a15a8243" },
                { "en-US", "e8822679f0050cbe41b92ffb123df5911dea4d6112d864c32289963fa1913b1a7ca41c2e5e7328e053c87ece726a947aaebf27b0ba0cb54ad3c1f3f7de89dbd5" },
                { "eo", "495fb2d44f562171c388c602c0d44b8c4bda121e2cca271dbb036883f30fd69484aeca2ad761b7b6cbaa047e1648e46a9788494bfc95bbaa58125c94d9ddb2b0" },
                { "es-AR", "7e7d27451032e87041e1a9c2fadef0d2e0f3ab44bea422bdea178bb45c913c5c7d29bd681a097e7fa75a2a29c8933bf8362087d32158f7798d3544ebe91844ed" },
                { "es-CL", "2e478e53cef061c57848fd2ee654cfb27014bd3a141b4b023aaa6a80433f8ba7442250080b6e94795ce5281b84b1775589b2037bfcee35d4dbb2066d0a251ce8" },
                { "es-ES", "297e8932cdd70f5381a693efeb5685d3a723701d4dc36589d76f1e8c067bfc0148d251302a7e5431e29f09e8d007ea826058ce06b93ef2a4907c4a2cb7b27395" },
                { "es-MX", "c869e646a43d339098ffb2336bc27f0071c9e0dddd3ceafb0675b775bced24afe970110bc234764963bfd5a4b43a2d19187666476f5adf6919de0ce462a28bb5" },
                { "et", "8e1efd3f62b528de140f7148d0fca4b50fd390689b6cb85df0212a3743d2f143208ebaa23f12e99edd785d82075879e964e83cd1cddb06959d909a7c99a453c1" },
                { "eu", "891d42f2bf0912761805f17824961903f8a57bff3414020317ad62d6cb8ea0267fa0d6cdd20fe2ab1badd1c2c76a87ffccf7355ad5b6b23dcee692d6d8a2c57d" },
                { "fa", "fbe926b4a3fc1e4946ce967e0378a32e91d8025de284bf68e118a3ed11db24fb254f979ba3b055b14cb38661c45993ec1d0fcefc12f94040c3afbe04cd49b1ac" },
                { "ff", "443f2275c4c35dfabfeda94f6d5358076c7d75e932f2a3cf8986fb6d9d2a3ace07c27446246332346b6e31efb59738f5afceaf6254f404bb57fb8f5bd24f5bc1" },
                { "fi", "ab5b030f122a45ffc52cb42926d9e32c3c0f68324bb9a9e4e01428b255f39a62b4270d651211127604f5e15bd2ebc1437362c689e6a8724ff0ed0f1e3d3a34da" },
                { "fr", "0aa4182c05d7b7e7e1b6eb27b0512b7254a16a2fbb0c18ba2579d6936dde98c1f359931341be1bd59a92bc7ca72cb4bb968afcf80d7fd76785dbde158af58d75" },
                { "fy-NL", "8463ecc80d1cf3678d251a243512bab8b964e4f39a4960ff937010ae8ba3cfe4d4f82c99bd099d2db47762685ce7718f339b44b71b5245e68addea015c14ffd0" },
                { "ga-IE", "478864abf920d2a1272f8879e7e3771c1afdcf1c28b0137bf3959348268fd87ec5d819ba20603a91787ce572e458a8c3eab07fc1b60274d61f13de877ea30cd6" },
                { "gd", "880c76e19d5ed2edf25ff01cf9d70bcf23c065d19b12c75c1fb52c28a203aff1c489471ee525d775b07345812f242c6af995bcf887db0e14d0f4bf493bd2c1b2" },
                { "gl", "baeb699b40a91c2cfb068f0ccb90bcbc2186683de50f749849bb3208ad358f94892fe590d646c4ba9c5f1a0d98fcdbd7f45f567b00193de1103fa964efb329aa" },
                { "gn", "4d29645586398a6c4e16051a3196817b73bee4b325d412fd46443d86ce4b4aef2da46f970690bddacf14f8181b2d5ff1e08d3d3da7b78a84065b1b375fee1636" },
                { "gu-IN", "821b49282b944cf8fc987bc4cd155efb0e6e8e0093d4ab37af9c1be7716b31bb8ca712eb517931e207f38d2e4ae9b7871ac66e660f35bf37ce8a35dbc6cf453a" },
                { "he", "2510deea58aa417f822874f00a7dd749931f6843b03105d3dd3b1244ac44e2b36e865de8da2210fcaaa110929bbace7799d12d0f351acd1b7353728a6eed6bd0" },
                { "hi-IN", "20184f86c0e26d1f5ecdf7b0b7c49669710688cab20c233c1f8c9f5d8a79b647eaa5b60558508df67d711fcb5ffebd001811399151a18abda30ef17ea60b800a" },
                { "hr", "0a8c046aec9aed5b3e8bbb41898925bf56e4161d6d3b93444f2f5b4fb1937dc4adefe2bfb217941c39b37b9e5b86d946ae1ef7e5c7f8b6224070c349735933c2" },
                { "hsb", "a97c72fbb3723379ca3799da2f9829fc9abd1703551b77bf103be47b03983ca5ad3cbd19075fc16de2e53bc455a6bce7be7e3d74d2b43122d199a162eeacb4ab" },
                { "hu", "198b9a77c69d1a3a42d6a66f0054fe4d56fb79f5f2783424980a0a75a76f0d8cc92eaf24c077c912a1b3e10ce0cf88b75afb74e47faed9d8ea45b7c5b32016bb" },
                { "hy-AM", "2d9f1fad7d038c1e9cd46d69171a03f68ab474021c995446be574f7d334d0a2689fa7192cfa0ab4386f925f7e4f1e2beb7358272d8223bde82083b2db42b2d88" },
                { "ia", "06782ca256ec529f75dbd9c586349759b3291087f58d8e7a994fcde2f53daefe6f5cebfce994a3ba1da89fa2de3d1f27d9fe38dd53824ce2021782f3bb6fc822" },
                { "id", "bb36339a7c1b12a6d23d81e9688ba732ef5c618bb59eb796883e08ff2e4247b093bc77e83e117d5767b30f9c43a2b95dc60313a10fc4cb78a0d41088325a0b65" },
                { "is", "1f05466acdb626c3ade280c510c7233fb9eee36230b48f46870f7e1c92d4e4198b129cb46ef661c213875802d2aa124d7a87296be27df36d612aad4819376695" },
                { "it", "a96af8b8959328e96becd3cb37b345272036dc92c4e9f0cd97accb35e7730ea1d5929feee6509ad24b486d1f1c30fb0900711acb7e7b2a5e808dbf1c39af9ecc" },
                { "ja", "a68a6c82f5fe57d82590432e199d1bb424dcf108aa9bb1b54907e9451ca13f580aabcef23ea686eb43355040c5443a51bbf7d2357d4dcdc3360610199b17baf8" },
                { "ka", "886dec4b8f9d015b9fea29d1844e55db5bfc8c13e2533f2ac69557499ab9e5e74862db31a4e912dc5666486eec6f24693b648324264ae6b5773f8cf5f7c6ec25" },
                { "kab", "952e1a3abf16c698676a8792d24a525790f43e38fdcfd080259ec547931c26cb412de3adf069dd011a064dd69b60c075975f35c16967ae03cc9a6a247b220590" },
                { "kk", "161168ce5bc930f96bb0a675cf3df77438648a4f09fabfc9e09f1b1a0e9c989b1b87ba89e93cc2de09b05de4191d6c51539cfb04158b3a1358cd0df82c1b4d73" },
                { "km", "bc6c98593d61f78faa4315cebd5082cfc5dc8caa530a4a255335b4416cddc3b4a306589db23cdb3a80a930560771ea774964cf660edd499bf9ac84a23d4dde25" },
                { "kn", "cf197884b569b5d48157f754e7c390a687ad65669f3fb8ad68f8b9e219feb3ddffe249ed876790c107574f9a0d167a0f26f2dbb5d6451dec37e12cd281cd809d" },
                { "ko", "b2a1dd1a774b50d9aa4329267597d2043d159d78287e769854ab4356fc72a4f61212e91f98202a4544d1e3a2d8eae6c2732a7637d563bd8f0c456be16ee995fc" },
                { "lij", "46c7493a1fa70920455067e00975c0b31de5d444f6a7f94cd4d463de114f8d8f59160287a61f9e258a87032d699f9704af6648eaee7813fba9c0784b24d7b46a" },
                { "lt", "26076334051bb79986a8f6a912c6f856b27c891074eca8a3eda080bc8a0026d42e369ee69015a3446bd48230d765c9c4f91ab5f19983f64b07b59318281c350e" },
                { "lv", "f8709eaf743426b601a228d69416019fae19a30ec87723a82d639f5c9413d1fae8c4ccf7bcf9132d2b667360e21be136a2d7c3be2f08cc59d57b0befedbb4e84" },
                { "mk", "120881e89b10f2159c2a1dd93581acc5d2080856edfff5e82786dd5abbaaa5369188dfe62ac63dfac9043ca20cdbbe4397c3c946915bf54914683cc1b0d569b1" },
                { "mr", "2fd6d53f7be473f85f58b9d3550b48b2da675cd63344f86524be649a9cddfd7ba9721b02215862069b1ce0ca1c5132c4a3fd794a4cb3afd489e995e8f45ac563" },
                { "ms", "4f628a8e16967deb0e2d9605b0c83e44697df7110c011a50cc43de3953bf11114549ef1266e1b84c130acb3caa2251d06cc4635551dcd42d7032cf4d0858bd7a" },
                { "my", "36bfceed2b81053dd9f3a95eff1a869942eec8ed3ed70d7cd5479f04235fc276c208450106a2d345823ad6345ccb4f62457916b5325f2fdeab9fb432b47cfcd8" },
                { "nb-NO", "1647b31152f6b32e31f60be6d1dbcf29b142ebd30cb9f2a8520bd398b8ef87d6861c988b60e84be5105353f259d551eb33f333d38fd70a8d5fa983912a808cee" },
                { "ne-NP", "4874f73c5bbdf87afd0b5538a73b78f7f6ee712d83937685d1df4b15246ae436d7c285320f64551c534a0351b3dff4dc6d41fc3ca9ccc9f968d5e1b8f74637e7" },
                { "nl", "0c0ba780b4571bf8649b6f066f3cffd4376966f8825ec4c2e59928c7752bcfc82ec0d9d96e060cb8f8f7118be6af8069e0c7c9d2dd2dc7c16a2e55708dedc9a7" },
                { "nn-NO", "b2837a24cc64595b15935290a189753f22514f17824945eb7a7234a471fea35e7b5a2dbdddaf6c2f17949ca181d2a21fcf9e45952a006bf6d393a8ce12583c2b" },
                { "oc", "4f68e0c423154e676f42d893761208fc9b303a1dc84ddb84a76019f42e6443693575ecb67cb5ae76ebdfe1774948e8f0bc00f44ebde19917651203142b6246a0" },
                { "pa-IN", "1a6fc12958404964d2a7ad0f0efcf6f3aa935862ff127017170fa85181f7175b453fbf393e83c773e001ed6bf6678332636d9dbb7547bf27fced1e588e8298e2" },
                { "pl", "bbc0acd006d7295edb122ee136eee7a6f6e71a28d8248712e3d2651a96950089dc840469b4cbacbbb8947078efc244f1701316db6dc6bd244852358cba754b7a" },
                { "pt-BR", "a21c53ce5554abf23d37b09ea061892c750f708613fe201cf298c2bf2afc72bed713c57ba783a48583638455283a43e6d1358705f4086a11d560719c3f88e799" },
                { "pt-PT", "4a33922adf69343d291ff25843bea051b11b11dc1285ae6ca7a3a3d612c910af6b3cbad7f7b63f2df20b7a72fda417d258d0e3376c0d7b6514fb4e38c9239de7" },
                { "rm", "ad49d852414419f0a0de3bab1f911c27eb7ccdde46e3a89d78d14a6e43720de6a05a294dbe044f6e69e51c7617e44e549f99384d7510935c010610aa8dbcfe7d" },
                { "ro", "4d863e754f315c6f52c2855d732077918294ed25ca8a9fecb07c59372e8805eeefd72a3ad278cdd969408e7690486f30ae071f0a7017eb0ab597f3da7cff9b20" },
                { "ru", "e639cb5a3f47f48c853b3cf8d9772012698f75978ebbe87989bdfedfc31f46fe436e1db549a8af48b17de51d38a327558b4ffc11a2ea3b3621e9156be9def08f" },
                { "sco", "d48a6916e31591618c63d033a0dd134abae5e4b646f5ad72859f47ec3b43a3883b6112f400b8e7f24da7bb67aaf59f220b066f20bf2d9f0d9c2046233d63c080" },
                { "si", "08f1525b16752d49ee0654327dd767c1a62b316deca253e010dceba26d3c136b55b46692377035bf10c3b36e9557b8a509ccd23ce15085aea77d4094ddfba19f" },
                { "sk", "1900331b22974a850dcd8345d443f76624fc30333695fcb9b238e2c09f82419d14dd26299fa265dfb73a3dabe5f71511873f2bb513e182ddf2c35fc9a5c1eb9e" },
                { "sl", "7258440408a54f1a800124656c9fd2b35e5c3345f6ce2d31c1a5b34a15a5be6bb2dc03e663e2d1035d8fc4c39df8c439d5c14b72bf60d0f0f31cd34efe641a0c" },
                { "son", "1c010f411a368badc99d91893f3a20de2e1eae5294227c4c6a10cced9282039a6581d6fc2dfbc3bd543c46a3a573223f54b675b4dccd4b96c44046a83b61c117" },
                { "sq", "7155a2d7f798ec8cf865ecf36ccc6cc866c09fa9bb9fd6461c8f5ed071b3c6c20628a9f957872ce4817030ea910760ef40129209e3b6b7e9975beb1cb8b3014a" },
                { "sr", "4307c10b022255c06d9cdf0ebc1411c591a2caed341b87934ef5fa4207497d8997e9e8fdb42ffd488461a4c230a2e65049b75ec6b4514df42d6bb70ca711e814" },
                { "sv-SE", "26165c86630d99cff78b711057595d518787ca02bbeccc5fd90da53e3740bd3bcd3b23ede8bfdf72e81c0592f68cc9f384450aa33cb55454902cc9a43381b54a" },
                { "szl", "f2bf3781527d8700e521105c2b5305d2fb7f6a1d0cc9576fca9d3820fe7cd7083cfc51b22df49cf237b1fd652ac17f8cf31287ec53ea588752aea6ca4f10222a" },
                { "ta", "600229d688a60df11cf777765fd23f8240cca5cbdbb2e8a9423a9ac4ce6f4d6f60c2bafb738271a58a29c9cab1948725637877454757f59f38cdcb0b95dfd66b" },
                { "te", "562a23c2b5bca0ea0d74ca060ace1ac5b9f8bf5165a9b5310c71cb2e548a413d5248902c1bf447a1c91a15d7eebbd0197c2fef80a7e66557a963d27e399f228c" },
                { "th", "13ee64cec5adbcd9a783bca6d2248be48b3e4b61a0c7257b241719e8e6ccc2336f2b309a380b0498d7420a7c751380ab58b81a6a50797cb6430caa117b105597" },
                { "tl", "ef8a2507cd04831ccc373ab63540ba49029d1f4d97d5697c8e6a809c5167fd4857b1ef2141f8fa417686b83812805c22a3874769d3977bd4d7f9687b8cca5fe8" },
                { "tr", "a318466496019452f4bd4335a51a1572cc9cdbdc47336e33484c6ae1e6b67736f75eb84bbb2f88dcec87bb807d2604816edc18273e8b8952fdcc0f20ede58965" },
                { "trs", "884d05f3e9cde7d92cb18c5f93aa22d6b90cb23ac95056694e883518b60b72d7ff31156750b3a338bbad303e73e35d8129fc176b41a6ec5ce2fe6fc674f189c1" },
                { "uk", "7551f6c38c7591ea1dab3f036d42df3dea10ba0ca3d8d69c6630bad258db48b5f2dd5c638a000c7f191d4d1a402251c0c2228328aa0bfc3c7ed78e8edc623bfe" },
                { "ur", "aa1e7096dae6fd652a2d26cb6fb208fc04e58445d1118109c15ed1366b879a82a1c462bc0df5f13fc5f0df59c632045eec679e586e210806a69508a3b471ddbb" },
                { "uz", "d9d6afb18b196d1519532ac32e3edcd48d2afc96393a305a94b6e311de692fdd3ed75115fafc91674dc2d0354d69dd0cb1d9cf4782a2793a7e623e8ce39b26ce" },
                { "vi", "c854057b6367f57738669f134ccaa1b51d7d4474946524ec199aaf2fa5a11eb4951ed8152ea0270886a398df9466e254ef882a59cbd48dcf5035bf49294eec89" },
                { "xh", "c89e8c9c1082c0faaeb81a66a239ca0a5f64081f3f1156eef9cb09c18f0c5148e8f5e9887419cd0c4547dfda47ac79e9a5491d39d88eb54c29be7d136fca8783" },
                { "zh-CN", "f8fcb9f5f44808e5d11d0d716196a9a6620934bc3531f1dd39d3331f8ec43f64f396e780d3eba37ea9d71127af1b45bfe08f223f718e84c3a59b4a7e7abaec2e" },
                { "zh-TW", "371d03b23ce72131b27edfdf014b324bdb0ad7ac7d945e9b1cbd529c0f2be896b60db153ab42c0099d4acc77caa5d547cefd23087c5fd9c5fd4a60f8dd0fd39e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.4.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "bd1d468d94dddba7980d262652beaecbf363f62fa40a896ff135909e96dd5db85a0543893db50b88e10775bd4cc0ddcd7da6c65914ce0b22cfb978c72827a3db" },
                { "af", "4a8ec1d405d4d5343d945f4bfe9978e1669701d690dd5e6252fb333c07cbb727dd6fa4e985bc6b24d48779faaeb691aa4a21c24c3b9a60f35900f941be35355a" },
                { "an", "5d4a95d086b947502e8e0f79609063eaabe5503cf4fe1de458d04846b51d4e689faf3297bf39d90deacf7641d84dbf5ed350e7e039e4471bebd55f42b941d2fd" },
                { "ar", "81792d722b9a61f8c96254d99724c7746ef45beba4aa21d51fa72326d022cb16ab306832c301377cfabd54541703723cc0740b483281114ee121e03ab1b0f525" },
                { "ast", "c327bf355baa4267bd7c5e9fc34da730af9a603353212548a46f9ac500c50783999ae6cc59639cfb0ef0adb4c6a729a4f08660f4c976eb4631802a787088c591" },
                { "az", "29ba3446f1cf79b0f04cadea03307dedbceb45076df59177d5c2d1551df7157d5193c4c5a3e3e652bd11bc40e4bdfc434282d8f5ff1ac08d0c83550a615d9124" },
                { "be", "5b16ea79784d88b9326213ad52f71af892073c703ff7ba0825f56f425a0c9a5ad558d39898d2e7ff452774e9e5a2b1810354cec1166b946081ace054acd08d79" },
                { "bg", "b1560d6c155d2f7e8cc5c0a822fd806f6b4a2f087bcf7a8263e63caabd7c9f9ddf9b44648beac6698f204e9e9d18f00bedbca76b919da641bed9b5911bd1815d" },
                { "bn", "1312733c0dc9de2ad80024c11a31fd2589fcd904067b0227d8c2ae383b21c0076569e13b5e3ee68bb200ab10dc76150a3b7c7a8d366f90e0b69ab2d0ca3af045" },
                { "br", "10675eb4e0541c2923f6562f13feef7bdfd2be83a9a4b2a07ea627d74c8f0d1963487920cd0ffebe38cd0798fe041f77705e17fb4a1984c15ec13bb455075e73" },
                { "bs", "15cb8116dbc99648ac2ec24fad0bc0e8aa6c4606b73e59b318ae7edcbde6d6fc9b8cbb43be9717d5be7c7f8a5cd69bbd49920d4c2010d3f83c67fcec92a40a72" },
                { "ca", "c5defc2936cd4840202958152bd9e74df29f822fed4e5baa5cccdfcb09f980cfdeb3644af3aa4d10c6cacb1a1f3889b3398174b9d0b8009c04c74264771ea86f" },
                { "cak", "ec2da46a23fea1e15cd2323219352bfb168d1df0dd1db96c442d1fcfcd1c3770b9b0a49de2941402558bf1ad2a22211a524105dc0229d4211ea664e5768a3b41" },
                { "cs", "d3ec68ed053f55076b7d0af2bfec7cce98015488ff1c4a538a14b763e224f86ea702e3064233ab1c9f299e64dd665e3a3db312a435af7e176b7e8c1b59134058" },
                { "cy", "ea61eb54e2d4bb7dc8372c12f7adbd657b60cab9722f676595e6f2cb567120722631b2fd7b6e0ad702637cc4ecd07ace6074f06c722626752510a692d0de5f7a" },
                { "da", "80b66d9608f9acb2139cc6c6fc377ca97e39899f1c92233a60998fd85b0d6365bb132449e8ad93be259cc08481c34a9622d6cc452fb44782f6c52f661567783c" },
                { "de", "ae2ee56070845428a1183d37c5f5ec826e5ee22dc5639f23e45c2da7d872dd34e90f1c40c073d41e0e9eb50319230b07f27b9d98d436456b127ae6cdc9e6a597" },
                { "dsb", "c7be987601423a92ed6cd7a7e7ab3cb9404b27e57eeb7bc4c8b95c1d4dea132f0f379148dc0a9ce6bffed5e68daf329d3148d732ecd2354c28c2e643542c8542" },
                { "el", "3480670156363dd337df8aa9cdd4edea1c5dd9493f2bb32250bb18b3f64b300eaf001e3153d7c1468804a0c51906841e8cec17ec86367710a0e9cc0f861ad344" },
                { "en-CA", "bcbacd94ceb3a7983362eec09578c4d88e3689a65ca1b673bfdb946e910641dbea3bf44028f5fc530c57c3f4eb8691e9da51c58ba628d460c6747adbb1bf666f" },
                { "en-GB", "3d927888c696c348079ca69de4ae92804c763e27de13e5c6df7a934f232c2ec2eb0f2f5f4083acab2a9bdc0a63804a7b3ba9a58972f845cf773ac62c5d626ef7" },
                { "en-US", "6f9cd6b557f8749550324f7a7b635f83e8a6b56b8302087b1810bbdbb5638c017810e8d2143b2eccfd48b130f63d63741c1eef00af2aef5491c0b9ea289c0714" },
                { "eo", "05caca0ff4c7e4e6989e55efa73ad6039107e69d1e8f2c7ff18a65d383925a4336f7cf45395aa6b324cd2c077f46c68bb1dc914a481d66ef9b506e511bb322df" },
                { "es-AR", "2da974206b873c9a302846558c1068cce227b2976e3546a4120cb7f7744b99063280502dcb18781f5d9e0de90d2c9138dd904ae2efec4f1d48ce60a25729fe2b" },
                { "es-CL", "413f391c2e2813dba60e6cc2857b47b3ec26238c968b28ea5280e2b607571b95d6513044f4a5b387d0991ce0efebda7207b6361f46dff73e1889753ab6844718" },
                { "es-ES", "01b149b0c5d9c150a0857f8e68d2c4fda75a18dcc50832e0251403e179e778dd827814aa2fe270f8747d819d40bbbb610f7e61a41875a16dbf7fae545863bd67" },
                { "es-MX", "7d174464c39433ecab934ede349c7f8659348a79cccaa8d6933a0fb723b51cc490fc1b5e97130d6b0cbad5558e6c01587d3156a34de7f315788f4e253e8b21e0" },
                { "et", "2d4a41fdedcfd10e2ad73f3c30c3b3512d86e385f9cb78d8c8d52f1e9418cd71954e05b07c9ef77892aedaae6ddf7bcd9d3a60e04dfc020a6f3fbd6c41940eb2" },
                { "eu", "4601159c7a8e24484a668d42988e261e2f659f3b3af5f896ccc429dcceb3e0f3c6405d9aef9b711eee9dc1b1dc6f32c447613a4111a4599044d79cfebbfdd0e4" },
                { "fa", "5d3c0396949f143449337a31a07e9f7c989efd96bc2fe84a495917cce488ac3e9ee811adcab476603709872c5f20f07a08731fee6da65571a0061ade6f48b06b" },
                { "ff", "4c213e523c90c31cc7957ef6f8b4211c64b731f984991e49b3bfb63889d2871671fdf3c94e205c3f797bc5d4751397855b127168904e0f09e19e42cdd54fa923" },
                { "fi", "a8f9768998065cdb2567768435df50d2d0f7ac35e7e9f18445b866942cf26f0418590bff7b095164d0103a8b6154472d4e210d0f6a57a21aec394599fbbc4ef2" },
                { "fr", "51b143b4202e23eb0cd2a5a69d4c0e5c2d3b5c6d7c98ddffd3ee506e20f35bb075f4368eafb037395b74d37f894ba65354769ea88e4a6e29a76f014c86d43590" },
                { "fy-NL", "692cc6af19b6f409b22b02f77569e58016ae2421f2c2a2f4dd60449f943007c211376b52faaf393013a2d1abcb2f0332cea1df7a27ec19561a1a8e123b126640" },
                { "ga-IE", "1cebb5050f514dc28d1f0598ed665eeb9c807b0327a6713c1ea02016e2982679c3bb6e13cdb0ab8c3ccc9a5091da2f1943729c315a010f0a93e507ee3e403f7d" },
                { "gd", "e13ce530cf9a02d9f7ecd9f1263750058adcac89d6ce6debca70633e7cbab0c357707c24e5994e136589246e0b9311ecd1bdbb77219330c9a906a71d24a92dba" },
                { "gl", "d30302ade70571cb16762d71c481cb2f8ed788a7c7e3441570fc7d0a34dae204a0d9adfc9b6147d9bca808a86083dd18ad9a2a01115db56c8e9c33120c349490" },
                { "gn", "196cecd0ad84941a0e85a3c5fbb03de22f3f5da78d4ae8af02f586fa847aec946ba7d17f1e9b0e669cdc3a680f9faaada422f0aba78c61a819a31d22237395e0" },
                { "gu-IN", "06fa786e5d605623f2ecd204cafc53d6f11f658bf19d863e35564ae340f4869b6ec29ae512cde6ef08eb7119fbb4b9c398fdd2e29d15662290dcfe65ac20ccaf" },
                { "he", "773bffef02c227c15ee710595cb6e9cf2a855ae698ac12681af59a0039ad7b69d95f2fd88aa5d2629a47ec5375aa3e859cee7e30e292b0ade3b83b85c2eb18ac" },
                { "hi-IN", "6f24e64b09e6d0c07fc6c34bf5125a6f07da7212d0b5e1966c1995a897bc3b21a81ad7b740c8e8c15b8f571c3a99ac3891a7825ea7ce6a5f810f7aa4440a79a4" },
                { "hr", "6fbccb3f40260b9e0c91872c81148f4a2f55a3f5f8fe775c7033ffb285e4d652e6bb3cb128c19b1131bf27530b22ece9753e421d1b6912575dadff58b8662e30" },
                { "hsb", "d22d2fa813682c5a405a78bb7ca5f6e35bab9744d66059a075d602df2636577e13e7596b55c5b7567d3c05465dfaf68ac7fb728d66877b86752333e2f0de268f" },
                { "hu", "991f35843c362750c2a2bc35d2fd0bb1b4b5445acf8b5be63ab4122b5b5b85b3817f706c1f3ff98c87740c041bbcafa977ea96c878b5e7db42f444560451b3c7" },
                { "hy-AM", "e487809964b324a65684fc55e9becd8aa0f93098f5f6bea7418e93bc62a0595e8287e33e075d1f4b9c56007e59a3531f438f4f7de283e3dd674ba4cf95fe768e" },
                { "ia", "ead5b96870f1cdfecc52744bc282f61be140942323aadfe2e08764e563fd781a6112f01a1b4c12b40ba798bc9407d5993c4d7f98185201f2e0447ae92d4bca7d" },
                { "id", "4de7fa4f7eac55c3246aa4cfe1eec58e5e2978480a65d2d277c0e891949aded57f68fd45b7c11d01a5be794c6ff06168e215526db09ad981135a41d5fc85b46f" },
                { "is", "cb880a541cdc5aa46448397313cfc6b671bcfd4db95d2411078cc628317f95b12d678b9c99287699aa8841ca0f1197a49961682dde00263f623c898631781f2f" },
                { "it", "400b519f418358683f56d95819922b19abfdc15f52e0b20474f1a05587cbe532c792102335b85b7316ea20a89304c8cdc374bec1d4393fe175e2ec6e9530f4eb" },
                { "ja", "95540168e8426e4e3540217079fef963168ad4489212a9b0c8684c39d16325583c559e2c8321e26734b168a29598152fe9a1f3bbbbf37118751a75026c23fc6d" },
                { "ka", "f367c89baba3661ae195710ceefc8e1190583a1aca67ab3d70ad77f5749ddc3c047a69fb6c8e3cb7847f7dc22c1d9d504990c762649fc2a13e59f7a501f9a3ae" },
                { "kab", "934e384d308ca14d02bbe06e360dd4efec69c6187d64a06b32fe88477306f6c4cfb70f496caab1ce71495cccaa7e0aeed21fd53c6c86b542f213650b72cc1059" },
                { "kk", "ec69cc8e4c1f136a3ad63d437cbe8be69ddce9f2c807d41efb8322ae76f97a005e1c124be9808d965e6fa8800b0e72b77208ad61999fa615f6b18350e1adb8a3" },
                { "km", "c5e7224243a765759142b3af87a3f92169e1f923f982598123b3a662fbef10a0e67025a2d6e73a997f0da7211989b2835ea495d8e64b6e7c1492e2e5ac0e7df3" },
                { "kn", "cc5ae8b3e9e94be46a4ccd04c7dd12993d1af51a45bad7357613bece936848e3c0b70391bbaa3b3d594198a63d7f74ed690a167b1d305e30ad31d925d5f8cb60" },
                { "ko", "ca76c89c9e4e93d5c0aa42304b13052569cf13071fa8d66f0b537e781b31444a48c9ca3623935a8500a81fe1c20ba67700d3632ac189ee5dbd2fb534f339006d" },
                { "lij", "b992f844ce71224ce68a72d55c12bb70fc5703b7700d1a9c80336fd84d05e21a4a5a66efb70e96b9b2144ebffa120d79ad4cb1e058756e47b87b0c9d41af1893" },
                { "lt", "58d4876d06412a374111fbd4e18171b0b5bd944e3c69ecb8ffb94f743e9546a25d81beadbed0c77683393ce73986a994840b070a472e4253155650455c77224e" },
                { "lv", "468f910ee376cfeb603ec676f0a914e6f14218e208d4b7dbc63537336d9119acb3dbccd1356938f3f6cf49e5db30e48f0493a7ba05338f8b3e82917bb9eb4f00" },
                { "mk", "03fa4294d59b8ce5df7a9a5ff666b22274a9e5c44c4c0e1c0ebc92c78f137db65b83dabdfea5f39c5c5a4dca60d8c5431f2235b2977759934ac1a98a7b7888af" },
                { "mr", "c6fc3bb7dfe5ed2a4854185f16a47b5b1bf557f853b3323432927a50d67e9f9a4a6b1fb698c2032dda5edab6a3c7dc8d05f7c2f02172684d2d9790a5619ac4c6" },
                { "ms", "9ae2c93a849cdcf20981acbcf98ebe33cdde19dc729b35c7739a9b2c9b2249037f1a2299efb0b8b311ea0a82902969bedc5214d7ac53c1125f31d9bf3aac5338" },
                { "my", "f947103405bc9d2cc697b821eb70840bd50599545edb508241a8ac53856d2714bfb50142ca9c0929697f40150f7ba44389f0a101e63ce7a0a163d4e92b9cadd4" },
                { "nb-NO", "97dfde1372d2a663fab7c677d1c7524de9ad9857486afe6bf95c867b53682605441d318b5e8d926552320658848cc9cd4a3feae5e92ea5512ea9e04d3fbc3eef" },
                { "ne-NP", "de85968220c9b78d4fc7c68029ce75b96d4720a1f236f5c257787abf7db13c231f90e6903b315be7fe2f334cd0b50eabe79f5c965117c81f19a9156f484da83e" },
                { "nl", "c5f25af5d69bb86268e8a8791cc5bb91117d97e738ea214c24a05801817fe30d238cf4c1e513318100e33b6c3738ea99d297ce0fb091f65e0741759582b5fb64" },
                { "nn-NO", "b0654c322085460560a6255e5492ec51c31478901e88ea9489ee9a9999f33399a04c9417934b9392154fddbe0697d064dfa336022c812609ccf4d1d9b26f1aa2" },
                { "oc", "ef57843badcc75ca6535580072e7faff40f8f3d982cc5316948ac8fc201d2012560ac29180e13e3fbbd03281e55df2c93c9b3be71ec029fdf8a9754506ba9be9" },
                { "pa-IN", "af8f05875fb3068299a73d2e9f96a75954adcb540829fab487b0a162ac39559fdefe159a5d677edd59ba94a25043bf923c8afaa52dd3b21361a3011ae9e53570" },
                { "pl", "4b3e0e20b08e4b97944057ef70494ce1ce7bd2942d19358b73b5a54566be04f90fdebcac9c47674dc2ff8778d738690b6ea8807750be581ee58c39ea3895111b" },
                { "pt-BR", "d9bd4dd913ecd7209b23103deb635919b1535e3dbb5808ca80170e2fb9eec3cebbe1a46a50c6bd165f1b2fffd45bcd165b4462514f45bf85ffc3bd910a3eb8e7" },
                { "pt-PT", "fbb439be3a951a10280ab0e34c6e5f1e94e269f54d46f96810821050bc11c2e7784504851739d6bd4dbf3b38c79be441830e04cb720320ef6bb67aab28e3dd58" },
                { "rm", "6fb3fc9ec36837de51de0dcd18628335a113066ee73ad241b07d8b9bcc85d242bcfb557c7c250ea164464a2ada4b5c43e0b3dad732aad58cbc9d92e3a5ac2822" },
                { "ro", "45d1951d4d61101a0bd3d601655747c3af07999c989be5e6d750b968105caf5b85d265354603d63356a764db7df727e4eb2575493c0fc00a7b91d1af1163be3d" },
                { "ru", "2ccc9eedd6e33605fb8c84e31073ceae4ab10846d7948e74d20c4e63502292fd382e58858c5cd5cf30c789b90f2a3bb91796e969c2e7ad9c4395b1a645a97001" },
                { "sco", "80ba3fff5b8793975f1c7f6131ec6a23443f0c952e9e40c76ca5ab701a4ade36469931e6693fb3a07a48310d953b263cfed444a267c1737a9f62718d9de3ab07" },
                { "si", "afcd75d3c06f0198c52536ae40f5c82f6f530518c3aa5698ae20264901e7934ea6739e941a6dd23a9870e3fadefcafba49e313bb67b393388fdc1223f105f0f3" },
                { "sk", "c691596ab417bb7851909aef2d8a43bda647d96b72937acb76b6e6a47e3d08fb519b6b1d4517994707916fc195ea189e5c36af580f3f6d8daa7b9f2cb430cf97" },
                { "sl", "c26d10b981f0358746a41a1f805922f34f5638ffa0e695a0f995cf6410da050e4a55f3984e1bbd00417ed626edf4a2ab4c5cfc4feb8914c061d3ef66ec88c78a" },
                { "son", "8165dec18a30c421d25423130213e3770c986c230a51b8d8a7934b56bb3d5825536fc2c80a09f627fc58b9812a087fe10505ba7cc03e67936e13d4b6c79f4e79" },
                { "sq", "69c47182b0c8dae62b0bee08cb086393399ae3fd47aab4c63f99ed603665012222fb96f53c8d202df3bc535f5c501e0ca172ab46b0ab0ced79a3d9b5d2c0d747" },
                { "sr", "d7a7079e3210d6783eec2a45c6b84bdde8e5c5de65c8c659702c9c39abc5a35ba34403df47f397ea72cd8ef3bca3c715d4fdbbd7b89cb0800a4f55e483ab7885" },
                { "sv-SE", "858c5df0fd9bdefe0a8953d08111304697f67810d342830e122ac6ee91795e8d1f2f6a7c42fa216c06d76b9ec4efdcac6a8135209e7b275a6b9aba7d81b03a5d" },
                { "szl", "3706c64f006f06286c08a7916d22063335cc3556453de735971a153e5701f99d168435a3524a7eb090fa199e72c194afaa5de759f6d155f22a505e98cace1e42" },
                { "ta", "792a3f8ffe79c6c2a0b45552fc12beed8df4e9405ecfe7e8972d21ab48eea3961c8980ade7d2422e2b2a4cc36a8b6c24e91513d31bd6f2449bb97f9a2b009a02" },
                { "te", "fb6e9022d1985ef099f39917fdf583d5e6674847c89249e00c1600613462736be3cae020e6c3216727ce2d92c810492f82aa0fd2a080087971d2a74c66942741" },
                { "th", "eebb7b646500965b60aa48e2f5d8f273d99aa1416b8f21c07e8b34f66ad4bc0b55ddd910bc6d109bbc63994b677c60c0a6cd8a8d9ae86fe7b532a6b54e67137a" },
                { "tl", "d412bd0e647d050cc45fbe3d6b32905092dda7d78b2e2ea644588161b3645a137b9b20d0e778cb880d7a6606d1dabadabde82345da1ad84ee29305a0f36467ab" },
                { "tr", "ed04c5da31598f8e5b81bc0224b88b1841da7f530ef4c814fccec7fcdaab7bea3a471aaf9f39d8f6b4b3e49d2842221a7d6c807f4878c271c8e59f59af985c55" },
                { "trs", "07309418f84cd75eab534a4b210fe9f52c409cae567386c52c77d7e42d3dc651294d73fa7f82a99f0951139bd31692fa9375e7b2247e81ebe9db882433283fdd" },
                { "uk", "7e227db801e661aa6756020d88133e79750b770c819a1e4a738e86f84d41c6a6a72c7de586f2023dfffe491b9a837ea5d2b34b50e0760df509c7d4b8018abd40" },
                { "ur", "1dde1332128101c44e0135b9e35da0681dc9cfe1ca7042e1c88cd20ccc58ff2cf454ef8dfab753d24e297fef75e00308ba41f1f5ef61d1d56e04e80bc0ffdddc" },
                { "uz", "3af53c013bbc5a4338e4ff6026cc5d8032290caaaa6e50f61bde8d79096730fb282fefe427c32826705e0f6daa4ef88dd5d18ee5138188ada6b51cc4a0ce3dc8" },
                { "vi", "3b7f3b24347e8eb8fa9df4ca69fe86cac7743254a2ee9cb71a2336a9ba17c0f7f29b2c77515bd46cd4170af7d1e9e7729e908bac851d9cfe01d1d2e66eb9dd6c" },
                { "xh", "313da457200ab9de2809361ff142e86d7cfba4f48b9cdc6caf170a4682eb4184cd7da295e378acffa7db71eaac0747e2be57f9f31850dd026e87756565ef96b6" },
                { "zh-CN", "1822dcbd9f6aca4569af3f5d89231f5ecc5839506a6f5e83a3ee566dd520839fedb71c2495acf878cc79bf1146eac6bbc6cc3b596f5d14bfda9b147935c4216d" },
                { "zh-TW", "e357476a1bc4797f66101f673641df98c789f542293ef48f481dd83443ec70d050b2d8c9dcbbe617484e9b3a1ab418f960400dcfc1fb4fb815845b5ab651c881" }
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
            var signature = new Signature(publisherX509, certificateExpiration);
            const string knownVersion = "102.4.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
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
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
