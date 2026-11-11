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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "153.7.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.7.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "9631f8234ee83136c77842d446f171cba49deac4938a6cf1354f6edc2773680b2ea6832c304452b77ed8c3cd683700377f3bd749b6647b68da494feb0f52cfa4" },
                { "ar", "c261dfc51127dff9903a37438e403035eb960ea29393b7642082e19a308979ea26c8938ec911505c6644a4d93ac64f8d7b76f3158b669835204a6e922882c046" },
                { "ast", "57855b89d82ccc9599202dd0ee201917fd93e873de40ffaa8977b5b598686a5d53048977c462885c4ba716e76d7881c82034e4b7fdc4da9e6be230738d7e8e20" },
                { "be", "ce52525edede16944c5bd5ba429cccade6e74ab8d3921f91f71461edcfcd7074d82ec5901b607b2da72a4177ef8b939ebf0966f6c9b8c7fa90e00dae18173cb1" },
                { "bg", "a8c8dca807e65cc5d7fd9aed73837fecce9380e9d9c398222f03e97acf62326ab1c9642bfd95096244eb89cfa5d6a5e3cbd92ac034a85288a6e85e016184b7d3" },
                { "br", "e498bf95b08064f760ef5297892f9d6d96404f1ce36f4c4f899ccffc6707354b55a8ca8a381e9f27b4aec90d5158d340d8815c462edf1ff62606e387c09cb991" },
                { "ca", "d72918b22e4bc1a550f330a1b25d7b3f5b48103be5a0893f37e0e2e96d08d3f9565f2e493ae268712281d86a7b43a8f6c5881248852ede59b95340cbfdc9c682" },
                { "cak", "5c8dda982165b0cafd717fb2bf535916b90da60d65967e921248e87ab2d65502ee45a77895a0a027f12e5f8e854ddd778a68efdeec1f7313485390db4f4ed66b" },
                { "cs", "645c9db927605561bd41f962cd429bb93fbc6ba7e3e209d1cb7337b9395cb699b309cfa3cb9a8d3ff896f120fb39ef0e9fc4d602613d0c2171be571bed950628" },
                { "cy", "2506a079f03151c58a5c30e8587dac064857d46ba18689fe622b578fb00b5175df55a0118784fb866be9b3d0c9ab81dd794d042e7a7e77efe7b4498426f20dd7" },
                { "da", "0474a10fa0592b7e2eccbcb6d8cf37e3c62033f3f7a472ef50a1d030c16c27d4672b50af51741e17322af7fa42950c885ee891d4a765090f5988da6173cfff7d" },
                { "de", "8352191c962d69eba1b4c267bacb0daed1e06ab6d947e0741f7dd263889dbd2542162c6853361522186aade14fcc9acd7332c1d3f728cc1bfc2c54540c156e93" },
                { "dsb", "fec33ba9dd89e27077aa4305bd90b5f48094a25c4f4201972d31fbae2b465970bc8d9bd3c638555d18cdb92de17e633e77bd6bbfd3eb4177542bb3c708802b96" },
                { "el", "9a75a8212522097c47bfddfe1354730906261731ee8780adb3ec16ddd213b305c254dbea6a735ff0b1708a2aa2fd0ff1b87f486fb1cb9e06bf343af21e79ecc6" },
                { "en-CA", "599d9e4188f3d0ff4d6613980a9ddb81e2f3dd3d4e29b1560daac49956c561955784e5f683845fa3762cab49d0c65fd19f79c8558890cc6c1d3115a041e8d1c8" },
                { "en-GB", "2eb0ba66c1d7c23de9002b6f077225e4b2f731467fe50a8dd888858ea04543453e2f90db1c53548a9d58d4c761859ad9bec76fdb802f2aa5b45eafbdbaa40bef" },
                { "en-US", "8aa6087619ab6b06beff8d1fed23b66b248cf40f84a3a575c54ae9442cb88e8af91849593f242568355cd5365c96f3ed633f7e083c3e76b42bcecf997ad04c6d" },
                { "es-AR", "94016b6651736cc4f0c7eaa702b2a9e1987f55783536e559aa25367ab101e11ad905ead1a474c57dd38a3d9630665a51c2137352b6a3074958fcd7842d70bb81" },
                { "es-ES", "92ff848365cbd5eec23fea68864033397d94673269b414a361380f11ee39390f7c8f81722ba4023bbaa79da53777361e524556cf2a243f49c861e03fb7188e4b" },
                { "es-MX", "5bfb82274a1fc856300c53ff96259bb2143d68c2ffaa51399dda8234ff1860d64ae0bc01b16b6178c398026bd2b503425489dfd94a3dbdb2c3b5d84e620087b2" },
                { "et", "4c32af123a46cca5d166bbb1ffce52fe666988da83339687457f713beb1a22ad0ae861e0244098bf45aebb2da512326c1d509490a657cda721bb304b1f7ff674" },
                { "eu", "de24ccd8ae83d8136a62092f567471108d7341966c72337de4efefe97ae093dbf8b396aa03eecc579f7bbe22b8622a456c79f7056cd801eee328f8ace9248260" },
                { "fi", "d536250c14de2f455b0f0e0ffdae1c5ee9ec3fd0798b08b4da1d09d65b16e4d9d0af2ec5755b373a6bad0e9adae01ddbe3b192dddbe1083865deea6a49d0a113" },
                { "fr", "0ecd8ad68b2b325414fea15a7a6a3d343914f153a16c1116d8730229520b2d9d36a90805f9b2b9787374a9d97b983e919c549ae699b06e237bbb727816f2f754" },
                { "fy-NL", "1f35fbbbf95c2c9afb22522740177a4acfd42c4272e59f9178c90854c4df709f5243d387ce84162a11998fbf6546e07c019c0bc85251ad968c43a780a89fd9de" },
                { "ga-IE", "c90ff6f6dc1fff0c4fd7931ac336686cdb8592cf327f773c17c3bd8536bfc87d7378ccdbfd763d16f1b098ae81f3fe002a1c9e4f5a758fe6895ba37011e995c9" },
                { "gd", "64deb2f9459993c2853ab2d18c70ff9823a91aee69c9162b72ca5a97a7e32d721d41bbe6f5ed1649d82c3ec1f0a8dcb04bb21bb9ac7765068e97f9cf6e37a14d" },
                { "gl", "1dfbb3e379432c1b7c6295bceb5ff8cb0753b06f5e905dda06bf089563d532da9ec7ac68deea177ecc98a2ded9477567cdc2e0847007aed1b50771a5d7d880b9" },
                { "he", "80561bf574f5be8b637eb2477592aadae5c5ba9261d1cb42f9a657c43faae2f87e48aa0d6bd322857f56d1dd451a65bf74f863c31e0266bb14777538ab2596c1" },
                { "hr", "8575952ded1856c94d3bb475dabde003abbfa01db32351a0b171624717cefa11491903010d22c31f474f72804db45bf2b2d8d6a446ea18a9bde2663299275572" },
                { "hsb", "2fcd59cd944ad5249eee607b8a2e24ff6634656d226d1b28f29f76751d3d24904ca46c885320f7f0662a9f8782ae48f41a1e96e25b7822f18b6e3294b9f1ceca" },
                { "hu", "3ecd436bc0095a10bbe3b5d17477088da82991c4460d157544b522e1775d7b7485a73c4bb99d0ee2e64b10bbb444878bcd2194e1431a095da4b9862425458fac" },
                { "hy-AM", "466da09b006506a95cc84f93b1aaee7a9588e3f3fe7b976de3f101fcc1a670bca50042edb73c8c58a59b6f1d2b3037150de1de2a9b0e5fab454b447d96df0592" },
                { "id", "df4a1fc3b34de33261ec8b89efeb5000c9c10261648910ecb60425359d601449d0b7dd9c5bd921b5b8069c109092ea0798e9189451365bbfa1dc4bdea3b7bfbf" },
                { "is", "8dc35f73b4c6a4c0d9b02388fcdc2fb36cba54ee14cd7dd26b1a2c57db018dad80e554c6cfde09d1c35ff81332e48d5bb2bf50df6bb484f9201d522120b17431" },
                { "it", "71e342aaa625208e437be6c25c5ab96167c7b0759595ab9ebed793bfa2ead619b0a49055528a30c1e5d29d5f6ca85dbd961672d04ac9aad128dc0b59789d3684" },
                { "ja", "28d60031eb028997dcac984dc0d7af68cf89cdf7b205cf787688a6ad38ac9ba30dbc048293bbd1042c2cffa35d04771a233ebc70fceecfba5bb0bf59884bc010" },
                { "ka", "101adadddcb27ca235108fc56756c0e7644bc20e6e638c3031cf63ebae42ccfffd9592e4514877da475959860b52e5bc504cc165a9d1581b26d11d9497dbf633" },
                { "kab", "d4c73bb16f018e53b9db316e308792d5bf9a5b0905a615ad698a253060db3d2dcbd8af7a505d825ee14da175c92ef12c48171c8a64de655e7addf7ce74ddf6c6" },
                { "kk", "c3ff3f7cca559cf274633902c08e9e573737118e7c2f27b2fac80e922a452d58af8e78fd2e1aaf9311ea31ef24b4212ca5d2a46681853eb781eb8ad1c3cfbbba" },
                { "ko", "7bac1ee1bcc2e01c1ec867b1290d133a068870507e80928426accbefb95391b385e58bcc0d82d5603d4b467a0a247d944541a05361e63c2adcde08f090a94561" },
                { "lt", "e4a4e2a079dc6e9338b14a5b54bdbc19c397d5e75c5354035fa792f6d6d8a9e8b9f0637166c4d7fc58665ddc876b81d036e98a754a02c7a8d6c8c4981b5ef4ac" },
                { "lv", "f02180a6a18f137c2220fca2f9e26d7f21c70dc2625a4bb7943113a5148df4c74556bc76377784df066cde6256904f39f2a650fa16d2216e348276aa9faa34d5" },
                { "ms", "318f57184dcf1553f5e6d8afda69df84f0657c87cca245f108884d6dca9210c919a5035ae3d662310d484a7f6df3a5d1b79314f76f4aaf68b55e9b9047490e24" },
                { "nb-NO", "d9ce5eec5e21ef21d183795767c7643c20c926b19221a077a88c97103a2658997f7c0483a2163ee8310d691dc4223be02fb12243b9e6eb68508b0b363548ac36" },
                { "nl", "05f8b4808bfcb596bc1b608f4c6390a4b80d598e4d24e3de2fdd8a0d73b4d03aae48015efdcea9a406b33c73ae2223c756f8abda9e229f9576542ed74e58e5fa" },
                { "nn-NO", "9c6a5a736c0a52075413e7f42e765d841c92c5e5b729bc622ccf1a7414f84ce542c942e038a381fa9a5bbfdf04575fbcd54100a8b3ce854d85a4c607eabf181c" },
                { "pa-IN", "c282d8d10d43578ea19f38d2798f782ddfb09e14256d05c818b93c5d620b4fb0facfea2048e37466ef18db784f1319361810c558a63e494d6fed99b8c84d5532" },
                { "pl", "fccc63d602ca12160005b8f19b354fc2ee9516366fb41b47d6d40c1ad99973aa567d9decb9e4427247ed5d51e95e7253ea684356ad5ed2ca00d1f8597a8eacd9" },
                { "pt-BR", "3412c189d35d4ca5c5ff29590eedfffbd46acfa8d5e8e71448b0f8d1b67747f51099475edd85b516d0efd33622b2065689244f21fd5f902e9528b05d086f76e1" },
                { "pt-PT", "7e1ee23471fdceced2517fa345c8f9d7fd0f6c206216e28127a70f02cf47157c49759fb1cdb3142b6626edb2cfef10afb604d4a19e7525f4f007e00d6aefaa6b" },
                { "rm", "afab08c1e138ebdf0a894eb109e4363965ba02b2c19e55ad5548907f2597ab6f3d971827bb3e135c52a31c6d11cd1e92df0067040fde5339d20ecdc343dff49f" },
                { "ro", "52c03c2ca5a3e7d2673df2af3ef2928ae34d546a456e08bbab1d7ed3b433d8b78dbf14a544dffc88ee59d843e683d64f4d468c749c964343a8aa76a778c2ea70" },
                { "ru", "014b4159a2bdd9145867e88087dbc6f7a306ee94b1884d0eabb6c2afb4de1b95b06a499150b2be1618ff8cbc9405ab622fa0567c056c18b38660c1cb258271bd" },
                { "sk", "aa31b2631b7272db2fe565127e7138b87b43f91bbd6b1e7567d935e29151f22de7ef4d57c3ff0406954590d945ccf6cc8bd140cd1ec31faebe5b05ca80429716" },
                { "sl", "d2e1b4cdafd714ff36bbb4c84f7873feae14cc52dfed6cec6797befc0081f187c087278157cefa2ab30ce796a275e9b2d8994cd9c324a66f269b31ff91cff894" },
                { "sq", "e964f085f03a13efd33d9da5bb2a343b5a97a82b25ab79945f6e3a8d61b7dea0e5a53d8f6b37bdd905a200cb29091428b73858251314eb7e3009341479f4f636" },
                { "sr", "8992fd27b8b062f9571f5c129b804faff346e9123acf4bd31a0edf8005b719221d08504e578c73a29a3512698ee29065fbde36bc3fba439c7a74afd2aa609aa7" },
                { "sv-SE", "4a977b06ce020be00884a42a0ae4b23eedd240943a32dbf2d99f2e2f3cd406937fb31b7136ee748f12c14b2472e9a25197afeec3c08cb9fb6d41e7a656758042" },
                { "th", "872b00841f392b68d5e8b78f61ada4fca344472d4723358c921ea4fc4e68114e037b1190a5837ebb9d5ff4f9711fb5d46196008597f580aa73974114f0c22dc6" },
                { "tr", "7aab0ce366f768e52bb1b24fe6380076d1e43e0b5676a0649cef34e035690706ce5cd41319aa2c9cf974b339e0badb377da4cd0441f6e930d7df9f846694beca" },
                { "uk", "2af9acd26358cb748b19202887e86ce0599ecaa5ca429e7be5ead2728a3d1ff4559223c6f759fc46795cf9ed6afef57dc01ed637410c5138f6085989eabc0008" },
                { "uz", "c11e2f205f1a3187e239606ed3f50c719edc465b1c13aa0803f53d1571aec4fbecdc320e9650371db6c1ffb53da07e740c2a48baa5445af7c62dbff32937c92c" },
                { "vi", "db0ef720cafcf93435eb712526b1824fda1e1a51f3e6ca57f91895c7a0cc16a03b5084211b51a5f3d5d7a83ff6be94ba7e27c6cc8c2f3a3abf406634a267ccaf" },
                { "zh-CN", "77e1219354116b5d855a39a3c4c53dfc2924d28b3f9f50ad8eaddbb5f4b109e38ec25eeea03e2a35f0980d6729dae2721cd2ccfddd304227dc005cbc0a11fc1e" },
                { "zh-TW", "71173f3ba9562046bde1b2e99234726c6fe3c793c9650cc8a4eab31148a24c50018ac65c3bb7060e3f431e6bf65ac9149a216259ae18e1ccc3b57a08e3b49bff" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/153.7.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "8f5105aa1c27d29cc6552124c9c78482841da07214a71ff723b93f10e1217d191aa28ee5394a3d6fbf27e6c4d6e3aed007df6cfaef5a29b18077e6ebc18a6cbc" },
                { "ar", "2b2deb7172c300a480560b41a726cf2a4124434fb6c8b89c480c3376970d540276c5086332e619436e6d5c527765dd25a85253d6003013bce3e84f5775906177" },
                { "ast", "76fd4accdfb4de6ee65a5b49b861574726778f8446da81e5cb476257ca4ce548ee2c672372c2074a46822c78c15ad66db51c92e2cb7f5d8b459a2dc2c7721a6f" },
                { "be", "03fa3d2facff8c01387296359855f861d48f8e59252216196831b0fc5c3084228a40323809bfc30edb060ce0f07ae0c6cf7168862d7c35f78421db2c5fc09d2a" },
                { "bg", "d210ee823fa8cdc73e1d806cbc1023a81c81c064b9242d712983fcf4f8c7629b337a7bac59ad385b42c66af2b8cd8e765de2ff1403468819b0a431461c80d0c0" },
                { "br", "a45502c96f7ca74aa824bb3f10718566f0955b16157586bfdf7cec4cd5c8fe057ef021e42ff0dcf28ffe7cde65cf07488a3fbfcdab4d3e5785ca83635196f5eb" },
                { "ca", "6e382415df57de67d93a7b3fc2c222aab44b5e6d181b2186b38563da701348c42d73d3dfb79bef287d071dbd7add3df3cd2da6e21c878011d6b6c7f59f545902" },
                { "cak", "672eacb84fa5858e33e37c44824756155ef4e36b9dc29ba2d67b41369b5a1a34cbab12bde73a8b8bb1486c80f7d5b36f37bfe029ee2cf197332246c512ad5503" },
                { "cs", "6426878a3727f221ab76aa0c976b08be221cfc7c6fd95e01689530e65de27d26b211c2b101cb457f85606a25d6f2ee19c1f781ed47659056b52fd27bd54d39ee" },
                { "cy", "9171b6baf0ea882975661ec956535e3823198570e681597aca2fbbfd988d7e915dce729aeaa030c06f1d586354270e331769cd50ec338a1a13ecf1620f172049" },
                { "da", "c9b0dd17cc96d326cde04cef7d409a90d1101b5038246173b39280efdd306a93bd0ed808302da5d170ac2d6f17cc5d44c8c1b7991629390fcf4dcb36d4579ff6" },
                { "de", "a5e072372a7da4305ba358aab0e2557755daa371aef0895f1037aecfa4600ee1a2cf1e93c7cc8c37678b533e496cff28e143effd5a029ee4a7a3827b6a0a1662" },
                { "dsb", "de8650ddc13132f28f5efd4129948fd5ceb14e8cdead3f685c876ef5eea32117212b361dd3a94309893e3b947259194158a7ee8d6c63eda438a5593b7e3afe3a" },
                { "el", "37647062fdfe7c1083885d36244387845480cac3481cd0f1f7569f73d84563390089f4a3534ae64eed47e5ef662971d8180fae9b244b3733eff50de2a7cd6f3f" },
                { "en-CA", "b11c3e8fc3591376182bc4abb1435a7e0d8cddbc3e8cac59c22ccc9ea831086fd17a8b402e6afeeb83b2daad0933a100cf8a7286a7fdf9084b09a9e7ba97dc88" },
                { "en-GB", "17a2f1fd69aed271b0fea7fcac6eb0416a8a1927533355cf9f0a79305a3b6440c53208d698c6850b41c6efb4759ff12cab844cf7b60425e2c0b256110b300795" },
                { "en-US", "3f97af1231c579ec7722b1fccf4276cabf3c411adffb929f194597208768ecdaf21838d2c0df4e33bdf38e1733b32e12f4d00a4b1e1abeb1112461cc0f1023ab" },
                { "es-AR", "23a3240c0ea3628ae34399ae30eaa72d83fc05f8a7ebc1b8c3e36f8e3c6be86276c94aeaaff039da9a415a8fb0b1bd63fbbf2890f65f61b8c138a87469e0e795" },
                { "es-ES", "9e095700b3a4bb03601df45cbc5ca718719e265e1201712c84f8cdddec4c0de497ea8c760954fc73f653b5b2551966689acd74c663bfa8a4a8ff66edd9f10f69" },
                { "es-MX", "c3b12e4b383d00982d139b995ac1bbb248d9b0a07a91e14251999f54756f2149aa4da8c5f62975e12eb6531833c50b888216cecaf766ea5e2fde3f33bb978c98" },
                { "et", "4dbceff0abffa25b043fe34efb4c2f098fa973a14cf9d945e4a34169a74e06e8049c67d628a7f05ee55d54e14c1ecb58149d56f59021c6cdfb321c40442ff36d" },
                { "eu", "23b530dbf4f0707f765256276ba42f50766866e8ed77623c077c28c5e375d38be25647df922dca463aca96e18cd4370abe23d6371f00c90ea02faa3d6f57226e" },
                { "fi", "d031526bc0ddfba96037e4291c307e17d10659ff8671552be82d2a3955d454420783567d05fcdaa516d8f30825a4293ef6be1d0199c40bd4a4c2fefdc1db545b" },
                { "fr", "f633805c0cd52d8cf722789c5298ca73ecd24c35cad085b0b8a074ee3c233c03e692f948a0f694d5c918124e8df258873fc0b375d4e8fa2f23095524d8c6622d" },
                { "fy-NL", "44a5c2f347ca2d9dcf240fc3a2857bae670f87ba3a566091da579e66691707169f27851290092c5aa7ebc5e68e4716b65f08de838931c6c9a088dbf639838c56" },
                { "ga-IE", "f12117af588926a6a61065404fb5a9510deb4a7c44ce922cb9ec275aa625b3b71a4cf884fb2b533ac7e64ed6bb25c91a4e65ccefb33dcf3d2c2bfff7fb18dce4" },
                { "gd", "5bc56fa958b2b93be8715efea192db5f5df16730ad007ad8bb30bd5a79237922cb493d3dd19a23074778d9ebfe4e3b6a91d40742375a756d567d31b198e8a0cf" },
                { "gl", "5c999961b7767190941a0974e2756ff8f84eaddb329a5f0788357b15ccfc69b8c986858bba1d2d5a56b7e2e637ab257eb5823c959d64fd94b4f3d51372b1cbf5" },
                { "he", "39f3d0207bb7a6103ed8f65ce8bba2e09200bff41dc30ed2fc268c097e46b6ce6f2c91df44ec1c9a26b610a3c8e8ad81c2fe493a71fb0cad4466b07ff49bf825" },
                { "hr", "e8d950f421346344a68aadfe6bd88b57193dd5130e46f0533950e8aa35cff8c9b3e10d0c61eac52845f919c815c5342c20d6a6ce2281fb3444e3035dfb038b0c" },
                { "hsb", "7aec082c62e5918b473e0508fc6d4b023aa90b4e052adabe3f0e424100a4846e0719549211e2506d4f3989b26dc6208077e59554c6d1245f6de8a219c30596c2" },
                { "hu", "934d6eb4826a4a8c03cd4dfcc1fc125c5feb00eb442c92e349d1614edfea505f5baaeccfd34c2b253d38887b626acd9fbe3ef6f5aa025be6400949826c9137be" },
                { "hy-AM", "c6f641b5b7a2c5a77d3fb42452104bd08d6c624a2e6a537278e57a2084089e21fb1d31d42314940b3f97945c8d0388f203a9ec08f2cf18c340cff8117fa088ed" },
                { "id", "c9ace1e06b3f358da82a79a13ce506325cbf7e43b706c472cee042598661dea7c46d3e243b62e69f3f56a195b82dd60f5fd7511a8d76725e5d7d645aac45d7ed" },
                { "is", "af91621ce0f424125b9ae240e79c5e7971a4cdaba74f27ab3c149d521d8a1fe7da7b0891164693643cda9fcb930b914d6c07eaa8b37e043f11ba81a8e44c1c67" },
                { "it", "3aed6d3378a0ca053c5c97a987032e005ea53058adbfbbbdcf16c51c96260485a0a7d87eb905c7e41f83cdc47fe00c93d0b9f0cccd43bb6ec6ee2b6b012f0a74" },
                { "ja", "f80a7ce54a16efd1d55c97d8aa694c73ea0aa394c6c96404edabe9de1cfcfa1fd347712fb4b633bda7e6a95fd0f5355191fd8ceb646eb8658484481d68fe674a" },
                { "ka", "6d589ee1fe8b1cceb782942f165fbcd76f96897cbfb5f783ada752b268b0a9539dff9d5ad5ed3e5e732447bb87b4816c479d020e0250da41280ba486ac08d4b1" },
                { "kab", "c8182965e5dc126c4c1b2bfb8d1b4a03472496e737c21f22b453a1fedad67e37529dfad49acaa772c4dd7fef09746bff0abca321535d9233d000705559ced3ae" },
                { "kk", "1bda83fa641d6f8e7a5dd7cf9dea0fde982840853042c2c49981b15d0515496a3be945cd45557bf5de1008334f003c2dd0a2771fe0db56dd23076fd8788c407a" },
                { "ko", "2c3182b667ec848844c78eec022b8a4a6f7b6f250d1a597080aadcec21f6a8474ccc0f7f244b6c1e292eb5100a7331e9fbb1686d3e867a7725f43fa39effa41c" },
                { "lt", "7c90e189b3bbcfd760b45a5a6de3552d6f6ec49a3303d22146d6633684ef065b09f283917d152c6f560230984b7984508edc3770d3a05684619ba94d81641b8d" },
                { "lv", "6fe853284fd20012c279a6b6fee4771688a709685a7b3cb2a85c401b922566ba1a97edd4a23748031e32d7559277bfe7ebb3dbd1d56dc8cb3539eaceb4e90f0f" },
                { "ms", "4ccf7ddc7fc22b0d93b043a755c78dc95469734089f1495777d2c6c52b56958633c8d9257d4f53694150c6bbf6e8ee8b83a9f0b55ab41fe8f41b74781f9540dd" },
                { "nb-NO", "bb4e3af2e0da49d272eac7fff23567d81d109438ef541b9c0cb47900e4ce7bd949f197d7564e2e307918a4ecf806642d32ec0fc699f7c276ef7727d1f0b58472" },
                { "nl", "b099a6392b79836f54a0f4dd32a50b674d30b026f67f6743d05403dc5c318623dec6307f22ef6411a2ee28b702e8b5005660efa2cd8c3bfb53bf4bd869c0cad1" },
                { "nn-NO", "175c2e44f8cc10387f81686f4688e419bf1a1e582bf507a1b2c3e415f9f13dce6b38337a31ac991f5fdbd63fb4cafa71e3f389eaa3621600ca501d4894383aae" },
                { "pa-IN", "a48f140f1003e3ab4840d6b42cf1897b9c6ef255ba26a756f07327393e5ed4c12140fba5bc302eadcc93fe5ae0aa32d40b31233b15221b3e6e768fb4a78020ee" },
                { "pl", "6167e95222eba3599bf159a4e6567f01479d2fcbff0a6d02028012065560a40955814c1ea8ab90a3649eaf16d06d7a6bd6a32d51a7e16382f335931a2c22d05c" },
                { "pt-BR", "3105d4a27751272a7884ba0024c40723b02e6b56be49aeb41fe9dd9dc5bfcfe232da3ab174bf12872ebfa374da5ed0f0093c90fcd698730bd0edea49f58e488b" },
                { "pt-PT", "789dee3d38a3ba54b5165726eb255b26518a1bb69a15deecee9ed287fd01f9a1b047b7de2677b18ce9100fcd036f7808762953dac2836713afd8947140e942ff" },
                { "rm", "b4119b1018ef310eecadc3b1554aebe9a935440b821dfd939672c2e0b990e9cfd0aa2240d90a6281601ef1ff808545e76115d5f2e47608a97bffc4d116e0f656" },
                { "ro", "e803fef2e5a996a30e2cf68b2fc91072c5090cc9caf1667febecdba6bb98d9daba89d7e27ab29999ffbf55095052840e17c40345ada0958f24570a6f5faa63d1" },
                { "ru", "b539a2529957d63103cf856765f2b92d66b8558f2ea7ca6571e8f1c9496abfbcaf1dde1b5e9b90ed87dee6d5e07907af4d335199ba708ba0f960d17d41fa9866" },
                { "sk", "f87e5acb8e5c046a0c44c1be3bf6fa64465c25cb0b7febe499211c6046577f82a9cedfdf5226a366dbcee37269f66901713ddc03c894eddd7fc4005dcdd08337" },
                { "sl", "14935c740d7f0e0729009a6d694fcc6badd12268230259513a62e69664d4c0e67c04f3a0812916d832f4add96b7907c92f9819bddf717ec7189afdd104922f35" },
                { "sq", "e8ee8b78f6f076b274f0ead729b24be02cdd162066093d987edea6f2785d585fe2e934eee004bee836102259ebe28586785c2203925491a46b3831c78d16a64c" },
                { "sr", "64a852aad4bb77228892d5bfe96b8fe7f96ec2db79d666af0afabba14b75e7e66adcf2522c8075809831a8831a77a7dd1b5c58778937bf7eeb0c8a0e40d93328" },
                { "sv-SE", "45ca60a99ae361cc69282bd631c71a8e1b2297d02066002b24111fe8074775e7c263a6ddb50e8ef81837aef064e03fd71a24ebed0eb21a42abffad89ae9a3ca0" },
                { "th", "883b8b0e6a3217c0ab16b05700d0c938f51efee0853f53db7499cc210bf00dc9c1e0cc0b8034435ae565e4c9114150ee1a8164b2d85009a6c17a05b3f0d23685" },
                { "tr", "c2a4119e4b251ba6d9aed8f3f57a7c6f5a9283506594accaab6cc55b5fb766c3cc0d010b71b13e7f0d499d74b961b9ae189e4f50426f5b67eb96943a484bbb14" },
                { "uk", "a4d707a5b5b310a6cf9590fbd6f4cffe22df62d027d7ecc7fe338422e39084132bd5a2621968fcc400db2523a1704fe2f0c18460680c0e4a09d02a7648850e99" },
                { "uz", "1a47810a64c9c5861b3bc9571c4eb60a014d040b6ed594c2bb4e4456ffe3c4bae3667fbc4c8885d3cd4b6822d9df0d1b08ef78d64d2b47258a262d291049c09a" },
                { "vi", "f43c69c7c1634f58078d24fe4d17bf7aafc2acf78325a918bf992bb2a584aaeabec1f634505fcf1ac26e068b7f61c871a351a3d2eaf87fbdb531e08b87da5140" },
                { "zh-CN", "97b08666bb6bef79d04adffe6c0975c525b5a8a124bdb757ba28e5ed35526dd0f32ac7cb1f5ad9efc318ddb2267de8e634cf3fe96727d1f99b50b595525bcb0f" },
                { "zh-TW", "f847a7d19aef2c21e1d1a0cc6950fc05f04286e517c8b028460c96264f7595b5b84bb3a21f2ab7c243c623847e837b16c92ec63b778bd3797c9a23dcbd86809a" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
    } // class
} // namespace
