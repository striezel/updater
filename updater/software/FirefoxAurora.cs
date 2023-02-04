/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "110.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "8a937ad97d74ea1944760858874d961202b75bedb22992e071c40d2f5e75625585fd49ffe1c946d9e35297b70ead717050a7fee99cd4ca80e3323184c856db29" },
                { "af", "463855561d6bee653da1285466904dd0fa9c0484d3d828f4a1414f84529cd4a6a055fcf8053cf2ea810765de9a8109d54b84c20da20bbf0c9d35d01f72c33ae9" },
                { "an", "a8690fcce1bbbc076a4cdb716d19f3594fd2bf8cb3dc7dc671a72373bf36b6fd22248512edd52bcd2db72de57d43905f5eb9bf020686181154ebdc4144ddf10f" },
                { "ar", "c3bf5c54d11b482fd83c6916265831df0a023bac001077ee2c527061e102c05f542e1ca0cd1f0d28bf4e5f3a826a8dbc54032fc63aa3c09821a16f693a9d5c72" },
                { "ast", "f399c0e4d40205a298a8c1653d0973ab030cf0523775d99e72a4a11e91487a7e6c027b4afa9e789bb72ecbb226743bc632502db394abcacbb210b1d57634b216" },
                { "az", "e25645b793a8ec48ab92c13b83795e88557e5bf7b62ac654205f1c7cdf53f3f0f681c5a336cc4a0c58c2337c96104b9b9409a3977accb854263430af333db7e4" },
                { "be", "72dab395d7a78a813a95515f474cf69a476b776a11266e973d3274538cddb455f5626071a3c0838fb8cf2d6bdc0551be890767df422d440992ccf375d7f72cfe" },
                { "bg", "b500692a3c69804a56df13cd52ba55726f47d55d8f0fe43c47c18fe42e0a972e2f0300763e4e9feb47b3057b3531ed20b1db5e8c1276d9fc6aba084c58f91de7" },
                { "bn", "256b00b5903816ee244f9474b6b5b1d33641999cb29bfd9c82073c1844fa84ca2688515e59ebe0cccf55b4e539e12017aac120ec9bcefa172c51522f4eba7269" },
                { "br", "7373ca9a824ae715b79ae7a51fe31428faa04ad84da0ab860f6cdaf4139a1f5e31ece8ce76808e7eed5de67ec8c98c59a4ffa41e9a06acdba4aa50460b4e84aa" },
                { "bs", "ba72234b47b11dc19f10426381305bae302eb629c770821985cb334a0092d4a22c502a90325eab704eb0c35f4455fa0c4ee5f362785d9b65ec75c7f3d9a6a603" },
                { "ca", "ac1b6557bbdd202ce2582c13e29eb645e97948246280add4e6c7a836784a5e171b9d0f915eef747fea7fcc6d06f6dc2dc86bd04dc55a301c569f5972f561ffd6" },
                { "cak", "7aaab2b8fc2617a7827acb8eb084383554760425e8b391717af82ef33afbf35ae996a4a18db0dd511bb11c836a963cd9ebe4f1837db9fe8f9824b304ab43d61e" },
                { "cs", "445e172af543fe7703ce50c26ef6c52c91c8cd286d3c755d9e32864dbfbfbe9265941370cae564831d3c4ff1d7c4bb334b8dd6cd576b8732a8605f8b21f9054d" },
                { "cy", "2d2b2b2f331c2dc45688704c2d9e4222b69e59426e52350f3a3977d7f2282d9692581a8ccd854eea08a2b0fddc21822930f2b4dcfa6921fcd1dcda44f1636b5e" },
                { "da", "de6542888c05e255cd993a6b00c679c8f63805de58635c30228a8bf18f74da39f4396da43df2727312c95e57a23b42e39f773f039fc13ba8596e0ffe5a89f454" },
                { "de", "36dbdc32c560e80442ac385c0571aa38c2ff764050662b2e191d82d2dda54a0a79c47921aad75bf0fae5b90961201ea3ac4bfd2877bdc6fcdf61b444c4a94609" },
                { "dsb", "ee79259dd71d8817a8a2c8c8a1e73285741c62d05a6d245748ff43c8e83e932f9774af7526cd8ad1259b653b355f5237928d3f721f10f882c88a79b5364d1c72" },
                { "el", "e28cf8fc9534ca77e4bff86f3e680558df6a8acbf0b9b6600d18d2740d9b2f50a53c1ae8d1fe439dfc213dd31c5f01c3b364456648ecc3c03f733e05661c6d3b" },
                { "en-CA", "2a73eb2337ed7f470e857ee02fcb2ec396956723fa7d079bd23a22cb2514668dc42795c5453017f4d8f44909c467ffe7ddb12bd7826bee63885ccadda2dd36b4" },
                { "en-GB", "67861a40954b43e179841bccd9b88fbe07ccb88f3d5a6fc6858225f244b0f1cda020cf83208bb0aea83f70c36817fb92e573b936756adc265b4477c1854083c1" },
                { "en-US", "fba1c49524d1dbb5338d0362c5bd4a8900440d715a22097a6b7095e044f6d3c4fa08065a204ce0e1a4cb1da86176b2d84a7635c2a4d8f91c6f7ea37c727fb218" },
                { "eo", "93307707ffd710f3524309431047b27e86e1f07e8854cb673006c4c17e88d344f0a67fe563c08710c24d849f25a1e4cc97380cc7f3ef9f39f4e783cdbe9684db" },
                { "es-AR", "4e6c45095088b08e97a43cf20be50bf353a700bbc053d95dfb8bc37aace4c74dc6416a2da9a9f89dcd494b5ef552274b7873592c2c971e881776698c66157518" },
                { "es-CL", "9a44cb03ed3e70a66b33c6dc130c5e19dcc565722eb59ea857d265eb64bdb9cd32b64f6db7aff346e78d61949c374fc13e725cf448ec9338037a93533b46c7ea" },
                { "es-ES", "aa218707b20302f270dcf63fb6ed8704227d379d7d83c75e30d99c6f86a7a5f1633e3da3958231fa9e2fab66eac678aee9eab5dc16f5b3a99eeec8ba5fdfa7b2" },
                { "es-MX", "5c770077cc524ac57e2261719a0f2f81479074508fecb823d328807ad8e676c03d88a72da5051f077efe1a399649b58bf5efd6086f9acd6f36ff84e07091fc99" },
                { "et", "839182f5800e953f80c134d5e17c1d933fbac11971e9ad8be92725ecb7b343e9196c391452de7bfc44418265335fd8fac2783efe7817c4c64263a81ffc27d996" },
                { "eu", "2e5b6fb1436268533286e01e936a3cc9da6f444a8769f624bdfd07cfb0d0270ec6d1703f42407eeaba51c3f53ed4614f848a8dcf5d4841b0e00d165791da3d68" },
                { "fa", "8dd77b75ce6a9c2659ad4aad42a407e42872642a893bb4d8abf9feb0c7cd03d0a774a56279dca282db7a8ccdf11a3c5b01176ce1664e66ab72d7106d3964304d" },
                { "ff", "6d0b2286965e50fed70265e1fd2da72bdb8b1be026d99c8ebadd9cc9dc27a82cf9a358704b30594472317b6b2b85f2b7dac7c841009ff2afc785a47a7822ac65" },
                { "fi", "0b2bd19194523856774510895ee956e532fc6bb5e5c6428ecc6a0b355b1a76e571eb3cc72400b1319abb7c6ba488e8b5497f3b9b4a0b316465d3399b566773bd" },
                { "fr", "9ec88a291ec3e79197bef0a3225042000a750d66399e77cf2dd7faf7afd8358c890170f36ecd4d395b59e959a159c6768045b670cf501bdfb9c4cbeaecfba97e" },
                { "fy-NL", "a65a373d10563d6fbc880958f81faf93d1a6a33ac904fc8006fada189d0a3f4c12f576c2b019183f28d9a67226398443ecb6ccfb082d39c501d8ff38c21d5275" },
                { "ga-IE", "ebfeaa0349a3b8023e5ba0e1fb942c19fbd202fd78cd1ac0f593d066531cf21a82e4ce35192ee83020f473ca4e7ca673a9f959e94329eedd4ce2b1d6b5e91467" },
                { "gd", "b34647b54697ba4c206173e45b4b5a9cea31c1f8361fad00b78dd31bbb039e37238ac94e80c1803e07a6376cc9edfd68fb3bbdf25134bcf9b53ada6e9060b825" },
                { "gl", "d21d7316ac544ffcbba93c63c273719d0c8410f2b6487a0a825fd54276bae593051f2e7e8111c781ee2943fac12876b5060ea0545fd24fa7eae224d6e54b3acc" },
                { "gn", "239c63642dc4ae6ee602d788519064d9ae8f55f1f8bddba97bd40e5cd694e5489a537bb53917221841bac524f6c63b5743e8863a8f1573a9a514cf7bcc967a46" },
                { "gu-IN", "5032514b7e3ed9e134d22bd2116a7a3e4f007ef41a2dff6c622af2e2c37d5f1684cdc8d34d8fe0674b2d9804ad661b81d5e99dc3bf54c2201a2ec638a48d3842" },
                { "he", "f7b8c4b267c7aa18774fcba8bc63154b99442c33169d5d57762edeb81af5d4e0373f9d7cd5fc0a40508ecf75f4b191591211abf3fa62ba23001003571613f1e7" },
                { "hi-IN", "b2f7ee9ad30a4f0afe159b7ca4ad22a079e3367c00f027d15221ba7365ccd3f80931eb84a355d80b519bad5063e445318f2272654db8b5bc91a3e4384826d7d5" },
                { "hr", "0854252bfd1a4ac7f667e07912d91cf9a178cb0b321dc9636721dde8da2b61a70f05106c9d090e83a15a8fb8f336cf4d631ada6c875f05269d2191ac424a9a58" },
                { "hsb", "7cfc28f2a449e8877442581fdd6ae3f0f162894b492d6a012a7354509e36a9253b4da96f9732ec49fd0964b6248dbf8df4940f47c139868d47fbbc0100bf93d8" },
                { "hu", "35477be7871990ec5f85ba9951a700c0bd435d35d4af79c2a78d4238e89afb1d138d7823f00fd94b2557731d36834f94aada3074ec01feb65674eaa90d7b2af8" },
                { "hy-AM", "db7b1e63499ef22c1e9e5ba4b87a9dfc78e237adccc31fc8219e348fef513f7c6b3eefaff80efb21d609160396ceb2a3d289aadf933172dd352e3cbf1e6d9295" },
                { "ia", "7bd7371d2b7caa2f65738ba9301368868c40d4ebe09b0c9381f27349bf66dad809dae324b993aa3cd61f8acfc4674ef23158a76ce0b94f39d81bfacdbb6c9803" },
                { "id", "5fafb865e133e9c238ba18a6e1f3825d983a0ebb9916c91879851dee3636f695718b6390bda7b85d61ee736591465e9744b33fe04a8de003293f4bd63ca43ef0" },
                { "is", "b31d9c3699e6d19f33ce50cb978074266796e8f215472584882ce9d8b3ffa096a517e8cafe8c71b0fed1c072b952451a5bc5c19e4254200228db926c1a4c8214" },
                { "it", "1c752f40b8137e70c5104b10445d71a75efc31ef21ee762868859df69e34329f4fdb5cdbbc05d9bc4975e2ab979bd18b44ddab0f1621c893f45b893db8022dfc" },
                { "ja", "0cd6a12c700633cdfe355d5c98bf8ca0916bd7edddbeedbfdffa877240662c91fc35d5612d215e87ef879e6e7e046f665e957d79a5587e075a48d5271ad8147f" },
                { "ka", "6d4144c2f9c6203a35123357fd1effd5650ce1a38ee3cff59876dfb253f44484b0970d1f1429cb2a132c820eff856a09c0d5b42b3077cee34f988155586c5f20" },
                { "kab", "a363f7ca96ea4b5e927c2dae7742d21c246a06eed8327d9d54b2b1005e950a9495d5078162d020e7a1b1e451a117b33159bfd74d3b0ec8fe18a8ff469d02689a" },
                { "kk", "3966bc543588f85ab38062f2bf0f41e71620e2602ebc77b4738f5deec66b767fcdda790b88592d91c026c882057086735d48c54c3bf42922b1ffa6f0f3ba9bd2" },
                { "km", "64d68ff7d7dcbce58f42095c145430d19c7915c0dd33ca007be840459cd924e7913ef4cff22b6fb1875f183ae7ab1a0405ab27b949d795a71ed2c0e8b3d7129c" },
                { "kn", "130bebfea18c60396891a83e280c14a6035c796bc9ade6ad16e87262e5be0a2c6c00bf6d68265e0b9d159f8d901c7f07de8b0b10acae438d27d921b88e4af9dd" },
                { "ko", "29f9783205ea3e933191a01594313547334995fdd981f0fc5b496e07987b4952ea52d87a25a1b9bd5ab5f0092d0dcdb8f9e49e7ee463c9435cb0dd8bf1dd5804" },
                { "lij", "b702144b84bc1451484abb5e6cab80841368de69d088ad6bf404600d83eba2f150e21a2c099f78d4eb2b68dbe0ddaea647ef8e678cc60febd764666a6fe9beb0" },
                { "lt", "c156cd88da66015472677e7cc7e644ec106b6db70b1ac5bb28b4d5c69546c14cb97a6e85f3aa52141f90f89d3f31c2211b5fbb0400f8c1f484c19579cbc6020e" },
                { "lv", "4eb332ffaf8a6f804bbe2137783824abbe23f746d9bf3f2465bcf2f5825fadac76d8e763bdb05cac6fa2322ad33ec0a788cdde26ed78da0309bacf92e0152027" },
                { "mk", "6d65c2ad83566f0b9daf045ca692f9ab9cb6bb5e2006a4406bc7fb7ff1f29fa0ac84593ba05ccfe4392785c88770561d2487088ea3fc6d95631a9d8369b6b6f9" },
                { "mr", "7c01f7580e0c60253e368b23da5dacd473ad16f6506ecbdaffb1e4851683794b7caf1291f7b2b80dcefe0d7b17d73f3115938fa8e79485038d8f67846ea43b3d" },
                { "ms", "c2b7647d9f21e288183665de9dcdd98c4dbe406d32b58886526ea185b79eb068ef9bd167a0577ef9bb2c1c4fd8c646ce2790aa089fb9b269803395ddc31bbbfd" },
                { "my", "6baba5a87c8be75920c2e9e4dbe84dd67af1a28936e84940978d3e6e0a112ea5e1fc4111d086fcdfa9f9aa2b8613cbbabbee62aa86a88cd78f34e5d9378de8bc" },
                { "nb-NO", "ba255cc838f47c8b66d713bbd2e127e724c045b5e93fb048059d66b58d98c28932be04a4328290d51abe582add582bda727612334a6bc6f31af0b3c516deb758" },
                { "ne-NP", "3fd57b60cb2e02bd4ed9d520462203d5342bc7f1e2932e1e308f78c16ae6b7d15a8dbc81b78c940895a3269bb5804e54532ae01a22a3ebf3502e189268cc7128" },
                { "nl", "f9069a56965a30fcc2d23a6600a666cd398665c9ab78cce1054c7647fb43433c29b7dac789e967665006b0829cbaa2d0b7b0f9ef19b978ca3779dd5055fdd0db" },
                { "nn-NO", "c8786eeecfe41f385e87920780ad889726a2817bc9accbd10953f570e074dc72f7d8764deda854920974aba50b80e030c452f4add1512d09b48625c6a5c88fa8" },
                { "oc", "25550c09c87a937f714de1a96a1c69f5b9a50bbf0ef31651ca2c1a45e808ebfa164723194a4d505301e22e59096f6582c8605f8f3ea51ae0a6fe6ee9c13d3c0a" },
                { "pa-IN", "60fe07430e626012154c03f91327c760e38dd9ab0fcecbe3f78d404b36f37bb66e5f77b0d6591303f1d1ea6fe5932c7fe3a5ecabb0b4ec47807ffd77ade55f28" },
                { "pl", "405465396c169dcf70efee480bbb6eee4e17c24ec89eac53d685f8c0f53221235aed2ad716c1cd60d287c9866f4a1a5d982475a62a1f5bfe36f06d740b6d01af" },
                { "pt-BR", "c2486410f28e110c6ca69c4aa5ea1a0a0285a3335453cfc0b87433d4cd694958905edeb5be64eb5eb047e7ef94dd06a01fcb93dc81d67fad0a5aecb47984d7f4" },
                { "pt-PT", "b399ca5d2079f2ff579b48afa0d55c2204e134e981b98adaff654181be8a5d502a3ab1b250d29542c97657b683ce0efb398cd74522cdcaee2356085e5e48905a" },
                { "rm", "3620c7faff43c9f6d4db19ee9bdd85fa7d5207e380b0dd470307ae1e7d802749831632be1344a4fe3cfa0ce9fc869ce6ddd863a033b37087468731226cd8d8c6" },
                { "ro", "8d07de1b96a1bee8dd684ecd6dedf0e81ea1bb3c215e5cc5646385916900c4a12582a28a7c7cb2243e93c1dee7658e3be5aecaacf8ff822a4b38c5b29a74eb13" },
                { "ru", "551b48f81494091934c7a52e6a5906f5a6edb1bdd26f893546b9b1876764be0dc313668a539cbbfa670995c1fd8f8a6408c79a9b686fb4a8d313e3561268f2e8" },
                { "sco", "af3fbc8fe9048efb93f030592dac9dc0d658dc5f38bdc058d23fbe5f996ea330d0facd93d905547413f9ef8e6cb8d83cdc9f12ce81dd52e177b86109823722db" },
                { "si", "bda1c4af5bb1080f205520840b43718db91ad3bab9c48bbc1a92bd01ce27345434bd6c85d04d4553d48703d446c8c53c22b4172bc6d02ea75191f4545034c893" },
                { "sk", "d44cadc04a0ed9ada23d74c1f10311d2566dd9e3c3e7f13d4eeda69661a0854432acda2a45e1167f944c85d277728cb091565cedaa10b17241d82f1a0da5772c" },
                { "sl", "7a8816573a7aca48dceeb5afe18a31626e48d375d6dfaa111df154fbf829c07a31a23addff98ade56660ba9f74524af19bf78357cfa90590749a5174b3719546" },
                { "son", "2a8854313291a1a121ba4ec3d6bd67267987a1eacb9bdbbf40b6c3e6e56a1250f0705f8f162d6cc131470e249b47c18db7222a688b1bf3ec4bc687b6f6698cc3" },
                { "sq", "7f60070b81a6946e81706a4a8ce38129128a3461f74e821f15f3bb9ebd4ee4bf198bffb7a0e41b9bd96cbf79d0114953145c99fa435b073306926a7cbeb72f24" },
                { "sr", "2af8f8ea3d4c6e25bd603dd4b464e1f4a9b5ed5ee6e7581821855e58122efcb1573e4f35f71307cd0b27e59f379d8266122ab5386552b2ec52cbabb58f3d9e33" },
                { "sv-SE", "f8e37f21dfe7cf285c3bc24638427fc84167e89fb1f8be1419f087f062b1a367260e937b1bb865727cbc833a951f59f54542a9c50d7574cf40bb11ee511f8f40" },
                { "szl", "b284f5c181a5d53777ec4534ced50400260243eacd328fef5d3a0cf2c29a1c53b8d7a8201674994fbe910ca1a347bc37e8cb1f17ed15f5126cdcbd0290ce16ef" },
                { "ta", "87ecdf3b69c132c88ab04a8e6b5fac73e19c5518dcf93f9dc0cf6fb198bcf8f4979b39930f8518cdbca85851197e936ec13ba30dc4d20733b83aeb89548ec6b4" },
                { "te", "54eda1c998c9921758750bd2bed0732b6ae82b90d1d341dbce18c9d615c54ec626a44dbb3795101fb3cf67a1b439e1fdde0e89516b0488fcaf37a1434f7cf791" },
                { "th", "5015d631a14b021ee9ae7d3a926d07e094ab554bea0c8fae66bcc39c51731d8f3d30adf90180798b0bdd2a486c1c0682ae17b6b81ea0befb1a5d665582836073" },
                { "tl", "0d03c774f204c49bfadf4b7685a1204c66a5e712ba1204caa96a65f87dc453dfbeef4b659e52d0bd376da2a1946bccfd182118566c0e43b26aeaf668590b6891" },
                { "tr", "77c5eca6496678c15f4e2bbcab85025dc220b620894389603be48708eb7ccdae3b19c03d29ee038e098af7b018cbf87ae8c881842502ce2e010328a61a583ac6" },
                { "trs", "3987248a063a10de5e0bb402e31f2253ebfbaadb4797a4eca2b6eafaefabc8d8605c3132e0065078d7fa049d79a108fce01a0e0f6c31bee5315a961a86482668" },
                { "uk", "a7b4ecd6e1557523a664ce1aef1dada32c2dcba444a6848a3904c8ba1a61c9b8e9eb33f0918886f084322b9dc385466e42fb307e9af6c484249a9e5c539a7728" },
                { "ur", "8dfb3cb561b86ed1387475202a924d55033e22efc6578f8d47e9b7028659db7448043befa8e59593bd98edd87817058158cd358ca931caa865830e9507f9384e" },
                { "uz", "35f6f7d14d8fcc998b5b662e5041ee897f8963b92a97cb1dc3291ba86542383122769d6b2c3e0804239794115852d769b1212454a8a9a8e37df8601efe9c25bf" },
                { "vi", "d3e6ca8bc0ed375731fc5b53fa4136ab0bc3508282f2504f9a77bbad999c590a0dc563e673e499fc7fdea9ec91b48db63f3a028ac2af30dd2f3375fa56db21c1" },
                { "xh", "525517e5203249111776910131ce7ec30831d767bb05b51ef6fb3cbdff9d12742a3cc5e7fc568e0802266b019f418fa2701a36c9c179f27ed4e5c0e6594064d0" },
                { "zh-CN", "e8eb2c542efe41347cef59696214f17b6d694c02ad46f325c1743bfc26df48fee3c2cbb543ec1656a856a70d411407d43de4746763c84ea851e12e0eec18e3d3" },
                { "zh-TW", "8d3078dde4fc2a64b3ec069c8913afc4c43ad99cb21db7200989199eef5037dc553a408ab3b1e19f44d8e5971adfcfa95d3d16e8dec95d0e9de011ea776c3a3c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/110.0b9/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d3fbfb3539eba8cc64a079969549959dbe0725791bff9f71601dc87793261d29363cf8ecbc10e1b7dc4d7bc0ab4517b65480717a20ec90ef3acb9a8c303cd9f3" },
                { "af", "8aca5c5b9c203f8b222bafa943eef36dd7e702c5a268c46021916216c7448397d2098c25f18d3e86092d7e1f2f4099207bd5b5533afd030a543f15682be0dbea" },
                { "an", "3c3bbda8a677e34ae9d0d7bc544ac3894c4ea0668d7ecdf41ba1760990c19987e8e7888a8a929582d2a5a2ce6c6c61c0afdf90c860d6c77ec82332e1cf636993" },
                { "ar", "9763659433f54509d108ce049feef679a72962efe355712c2ee7ae08d1956bcb78a8489db351c7795886e46650f3cdf6a3cfc6647dbdf632fdd264060b2e97fe" },
                { "ast", "c6b88ac3de2ee4396e7f8e28fb5e124e7bd21097071f159b094e6b6b53c61de52da1e285b7f2d52d887b25475c14a61fec2c0526a38125f23c9a04cf461f46cf" },
                { "az", "1213f457aef929e29f3c32f3829462e333567e2f2b9a5bd1641f6680d636d5df579b77d043632b5209d39b364b4d5cbabe26c528afc48950fa200b8b0836599b" },
                { "be", "c765d0e78cf699d6a165b8900235b5004865cc47a03543ebb7b2aecd50e60387cbc35e6fc7abc370c23fac7193d3f6e061a892f5464431cce5515d09257643e8" },
                { "bg", "e4d60efdab7c158edfcb1376261fa61c69d9988966dfbde85d6d52b4177f58c0689ece072912703a5fad98e7d887818f602338a411712549cbf014f96c15f5fb" },
                { "bn", "ce2602f0789dd91fc9d763a1c3854e3184f3c7ba6b1786bcf8e9543b8add6da46340315f7d632b30e1b3e3e8cd4ae3d9cdcbc3392c63a7771f85c78a44b20d8f" },
                { "br", "276d739d05f7c9ac921688a025271739901fb4d2752413ea0b14a0bda6446854f3748a1886abdf21dd19b7c824463830380fe9b602f6043766a6a516b43b67a9" },
                { "bs", "75f16d84b11a199d7d8b698585f214e5567a0e02c539556ba4c0a7e8b3bbfdb06396eaa0870131449e521ee1e306ebb3e43bd8a01aa54694237ece3c81594abe" },
                { "ca", "94ab9dcf9bed9964e3875f98b5142132a490a3347018e10b8b11b3482840190112e6c1f0adb5cbe118d3c7c33001619b6a9ead9bd6ef9c57410236067b8e6e6b" },
                { "cak", "9e494547d602b5d7bad01d2dcbcc636786d333140f1355fceda5244f742db8d5795f629fb25f03f7e499a3cf30ec7a3fb4fdad029e717e2be49647414ec43b3e" },
                { "cs", "4adab01e0baf18e356d01183a1002bd395240b2b2749eb6195064565dd48da849658e365545384edbc9c4b5a80f2ebc61c71d0c2683af2e0db80ace306844e79" },
                { "cy", "fd2a9bf9434aaada8aea0bb39750e3ff41037636bed2eab3a20b8c36070fcca0ea1affa9e4b524b99d418bf24e19b9f378d2000b40957de4935b85fdf7b0c0d6" },
                { "da", "be5a9ad2e59fce7faf30ad43e3a15b7936ead5425520182dad606b367daacd018d81e4b766d4331fda329fb4f884101f4b543edc5e3c560c2ed82c060c401697" },
                { "de", "e221effd247e17630c3e6efd1e746ba5c2eecf516151a6ae6e307983d0899ba3992d82c468a7c549acd1d9e4785e8f8bd19dda4af6d22e99e15cc10cc8a80ed7" },
                { "dsb", "c50a81e04ed11078158a36353af2abda412b1ff8a9d103724498f885c732a5e162a3a60d5ab8c6034c3058335983c7f01e981a7a30e954c3842d893b2fbe88db" },
                { "el", "cf010d840a7c7e5432add76a19064a757f391447877c0f1b1bd9bb1d60571dec4cfdd9e071572498629f3047bfdfcab0cd419f23adc664c9f74f7543136f6dcc" },
                { "en-CA", "ed8975a1537fc6c570976f10584e056ab58bdb21145b5970b961d843a4cb747118fe02ef4a17ed816f90dd089493e5de9f4f26bc01224ee6288a01c062c3a498" },
                { "en-GB", "b5085243e62817271e2ebc2b368a129940d45ac21727c22c4ed3505df9f39dc7af3ce8579e794fd10f815cacad31874dfa82183a64fc859b670842f9808c5c9d" },
                { "en-US", "ee5e3d4eaead0241e3af1ce2364a3a156c5bb0109cbafed17cbf0f0a89359929b255c4b7abc0bdf6f80adfae146e662a4dca9c2b63c3cbe18c863a5bc7eb8103" },
                { "eo", "037fb8e2e3895fba542e3bddce4d908a30f9636c9ca8e74058e590510ba1181dafa387fc5c275c43ec2ed7bb75fe8487d86bf44457b38d805c7b6f30da66faa0" },
                { "es-AR", "d43cff7701a762bbd4536aeb55511298d474accde646b75687ad32817b4139f418034e02a6040f859e47f6550e8206f21fb3d5e6f2720d06b66d99060cffc000" },
                { "es-CL", "f507af443e3e227ef64dfc846fc68475528b292e3b99a27a59652bc8bdf62749fd971f17127491328b6d48c6f8309511c3c5987fe37005ea62b00d21d4b50782" },
                { "es-ES", "42004fe4072a5ec1d434c432543592a8cf3fe509f74a85a1931ee935a2397c100592c3c2fa53d0dc924ea09d4428a7f06a7267d77f902fc8f908c583d54af94a" },
                { "es-MX", "c723253346f574fb4549294738e6e0b552ad5870dfe5dc2fdbe7ce93e7ea193e3c4e43652a2fd5812ac87c6f3a63c1ab0857fb304e4fe40a985325d1845dfb60" },
                { "et", "8175bd86c7f7eff9b83eb1e7c8dd9da17af25fdefbb0bb5afd64747e38841a0f472cbb0dbe74b257ea366a40a05d7369f5a88334c11c46e1a1de32f5ecea11f4" },
                { "eu", "18d5e2ca3183729981c35d9d3bfbb3835b52c57069d5f3ecdc654af211c49125b382f66b1308570367b764e2a8062486f33065bc20a8c5b7cca259823995c683" },
                { "fa", "e8b8fa9c581e482bbe303aa1f6c3d4943f09a0777c0e4ecdd0373676ec33e4abf8d1661bca27846fc846f4f3f015073fd2f38991f4e46807570b258ad8f2de9b" },
                { "ff", "f8e590e7bd91e0aaa3b75456aab0fb2104f45b51a9dd7ea70ca2efc52aed6222e247499e6fdad3c4cea71fb34126b69059a03dca90fbd8a25e308718e4b5a36d" },
                { "fi", "7de29a7423ac76c6d7812a9422815c8440f32f22ffb9b00b14dfb3cca4d12e2518d6022ea4592cd8f0b9f01bb87e2680a07c40de747bd804d7ff4a75a6989ab8" },
                { "fr", "08f47151f92089d1dd957fea8c411ca6a2f6f76974c1ae603aefde93ea7d75612fdc5c6bd750a3868e2318cf23bcdd0c6dd7c22e1efe694dab85a4bb8910a877" },
                { "fy-NL", "a48ef8455d3b35fa3aba6cdb475b0ca7167baa29887b560a2276a3f2a3400ec6a74b14ec4ef498b7635794cd353009bf0f06fae37b274b4387ba11bd85e0e19e" },
                { "ga-IE", "922d44698444f9a5141f3984ae2edcc32ee0dc3f6c3f77d8fd4fd05c335fe671d93de305e138a45bd9908c59f9b1c9d74b2ecd1f7a1f5045306ca555e27edd76" },
                { "gd", "8eabf392e339e6bf7b25a06cf21f9a170a4f4c6da079b76865db16114a72c344269bf8377acee81f569ba634490e3e7fe2badcca8d960e8c72efe545f622b698" },
                { "gl", "4f1f97ccf7246c08dda19c65177c5ba75c4672436a7add8197f2136d8ca1ea1e3ed8cdec42ae0e551a8fad12b3ec7684ab38bc952c7bfe06d6ec3821f95d2b29" },
                { "gn", "d1ff811451898298623d456d9e315af7ca5fbbdc1a5a5bd658dd4bb541533ce7a36bfb5b92dde8def57c08a6a55ed88d29ced11d523605d541017eb88364a68c" },
                { "gu-IN", "2830cfe8ef2cb69e9460d43566abab1123c0e49a6295da0c387ac8198015149baaae7bc6a69b57e82e41c545c212ee45d9ba515771bec614d14b149790c7e4d7" },
                { "he", "b7a2f8d5751fd772b0681b1ae36b5768b8d3fd4061665478c732df3222aad4ed0800a088bdc97f79764ce7c2988590c50a9aeeb7212b501e0f40eea2d2e2efed" },
                { "hi-IN", "91484653488acfdb4dbcbbf087d2dd9d386705ba452184aac0d1f24a9df114f3538106965efcfdaf915257a432ea8aa655b7b7ee3e91f139b0fe8cb888c0fd0c" },
                { "hr", "d0d6eda037df7c593d9eff6b3865bc564086cb2de0fe5ae6ab8a38e392d9955884a1075c5d2adfd7bc7f7255bb02d6a0c4012628cccf9b9f47018dbbc117035f" },
                { "hsb", "0f2041f11e74242d7e6b462ecf5d6ac4ac1d7cbcf8e723a1bee6117b4ed3fca0d94a9923c4b1d43153a989344db37e3608399424c1bfb81d94590a56afefe648" },
                { "hu", "d8b332004929133ea7549d63dcae17083b1f61f45fe8b047a2066bae567295e8ebbc15edad8daa12ce8b76586a9d87cc15504a1330b924bff0d24dade5fe91b3" },
                { "hy-AM", "9785bf76260d8d4e897ef0d65fa455ec2a356514aadba0dce66924f21afccfb20950b23f6893f86292ba534b6dd82b5b1c240658f95a1921aed45f5a17407b51" },
                { "ia", "9bf50b955c87da605c6b8eee4436f808d50d1ba970ce613204c1f4b47afac72b78d2b52e121ca7b8a8343e8233dc9213db35ae11ff652201315c87fda40ea165" },
                { "id", "d2bf313efe78e2ef9548bcec1f0f2c4435ff7576e7a5c63dae22b5c650a8f394fea563c7ead85a4981fa1b24ee690958b661216cf16c4396c7accc8840068b59" },
                { "is", "a884c52fd23400b24fe017b38b291edd3bd28db9debe81cd7e2e18ca681fd9920c9d18dc12405e7ffddd2e2a60db24b460be59da9a94d3de0620621e54509428" },
                { "it", "833a3154fb6fcdc597072b6d9feb0da32475a70b62ea212aab2890e0d3182bc8275617fc149efac975dc32f42e85f32ceec719f02111834fae2c86951fa3b441" },
                { "ja", "8f8bb8225fd7d4a78f1439310ddf61809bb89fb63639f4efd048ce9efeb7354a97c4b43104b1c13958f1eb50e5fe2e56baa953b603988b712a37f514706ad54d" },
                { "ka", "b6500dadf479c2c8cba43c32d6ec9f542108658a71d38d41ffd17e9a05c8179c4c16487d87873d6c504ce7cc7ee66cb862f8054cfcc621464ceba96af6646f36" },
                { "kab", "41df0c6e46ce9775f6e64cf55c4fcbee4121606dec363ae328e4f20b30a2580539602418bee8339b4607e0e4773d2201ad8ca3f2ca4f4470fbba6f6e4a60f941" },
                { "kk", "09376288b976f54a0ceeaa363fd7db86c3788610f5538d9421bb05344e7adec2998110ca0df3c9df8440e96b8c0f90d5c5081393f1c8459ed1da362583e31726" },
                { "km", "d991a98fd39af5dbb91cabb0296426bfa8628fcf789a9caf351d1811be8fe24ee655bc798533f68eaaf94ca100f95556d69d908cef5d9bc4dcbd03812ee6de15" },
                { "kn", "cc7e96440f90b04511e4098a8666db4ac0b9db2d3b4ac8c5604bff27f9f422e050abb434d44f1f203ebc61d454a1299f53e70afd6a097daa45202cea5ebe237b" },
                { "ko", "fe589dd795278dad8640e93dfec9a7e1397a891bcf33a1eca5fcffb583d19225cba1bf41f6626fbc56cfbabc9132f078fb7c53fe9452470afdabbc184c06d65c" },
                { "lij", "5b5475d02422406387c98e12dcca6fd156f657ee779cb43107eda8324c6d34743552410c1da23d9d9bffd9d916905dfae6e6906077649a5ccbb65947c6c8c50e" },
                { "lt", "c7d2eb4cb174d655f7370c6d88c02275bc157805985bb363ad173d0a4ee9ab4871e0d22754f6b1bbf5454ed89ac886313b0ce1ac8da2cd44c62830f93f9cee74" },
                { "lv", "2a25633e5e3bfabf969ae038593cee71ff8e7b848bc854cbe6799feba0dc74a7b7a9da381b8c89128bb254f82995fa8a6781080f37a98639457664a677caf4f1" },
                { "mk", "430882ab43996ccd9e5276e7d5964cacf3ec8fb83490c8aa79b21bd373b05b941f6755c9205856b833b9161fad27a234590742a36d4a528896fade7df4a24d7e" },
                { "mr", "e2744991a7b75361aca374e51fcf5c826bdd50ce334630fac8ed5a81100fb50c9c8ff125cc8f108375285d1f90cd6bc2db21a5c42004fa185005c20faddd5156" },
                { "ms", "d30a6f31b83cf3af588e90fd45c4d4bd0813a0ac83cbbdf6f7dc39bd6f0c2f5528917d0d6184efaf2e3324ca23272d08b647090d8a425417affb09bed0fd6446" },
                { "my", "fabf5bfb4489133093c79dcb1693aa15ae060fdb1bd0ed39f1224007210c4a34b76c690cf065dfb1322ec65a861a10ed4222f62133dcce717555273aaef49a1f" },
                { "nb-NO", "162c271198c15d22aa5f3d744e598b0ec5a22bc33d3a57327c5ee8c8fa6af0f6db10870457b6ea2d4414660605070ff265c6d61461b9be725d017e1b77296427" },
                { "ne-NP", "b65c774d7ca7b0c3576a4ccf24aa6e139db11eba1564f92952dc8a8cbb1d3161b46203e9c8329f3f21002eb06e6568bc6b95556910bdf3be3e5a25126f5d3824" },
                { "nl", "59b8bf9f6894159c9bae33a1b8d0d988e84aefba0f55bed4e6b9b3ec9bb2df69f4a28f9bc3b075f1213dd02f863572e13d23bc4311b6fc1630e739c6c83fcfda" },
                { "nn-NO", "e230773161afd5d75fe6247a676f4893135406f642a429584d7aa000add1d84e9086711ca8714d57430d129f698e5ac0bdd141fbc5f78200726e7fa00e7223d7" },
                { "oc", "6f47afa11cb66fc7e05668db572c8b01dd87ef100e63b5e86b370263f29b32a26b8abd3de506a133cfc8feba433ad8708c7c63605d2e84b8edf094901644afb0" },
                { "pa-IN", "39e249cb335a9de533fb37ea68f62e5d8ea48cb0356bf9d0bee72dd2f29be9ec06e4f8658fed58641af65680c521923bbb64534bdb9096ab4b36c3814e55069a" },
                { "pl", "5875ab5dd00b34a0f38b372305be8e2275c6ebbc167ddf6e4799a12c9fde8852e8683170a683c0a25aa499d1c24618dd928f3945f59ea810f76eb305e40c08ac" },
                { "pt-BR", "f062ac9ca1ba5a4603306fcb61130f4db1e9655f9241cd83478e1d7a2a7a32524534c65fb1ba42327b5a11b77c06eac587b35745e9007ef16441cb6c6f33d57e" },
                { "pt-PT", "38292812f4e78455109a34afee7160000919b2331d85d3409744a8b2fafd153c5bb35d82110362eb84b6e95551bf3e580a09ef4751b3cd0fd8d8e039b14ae05d" },
                { "rm", "58db1dc8814d2b0f8451419bc6a82e28c6072a067bb6416dca096a0fe090576706bd2f47c5150daa5509f3c614af4ceb179f6f97272e1b242db7e0b52cb88a04" },
                { "ro", "3bb68b9e9ec315d350625994cd1066b7cfa758d954ad6ab96e951eda25a8c5f636da31457c242b117621ddc04a1a875548a12f5d4330d59b87f30132b4626609" },
                { "ru", "e3720c2daaee2317d41df2dc38d5d009bd8251d5b64a35f34878c0c260dd39ac8f55a95cae70947b2486605804ed4875751c700553f115fddabd15af5dcedf1a" },
                { "sco", "bd0eabd76780969982b479000b51d9d4ab805b5ce1eebacf36a62b455971f334245d547d795bd57b497fc048360863002a78ae6a2d5abf99ea690ac44947b8b8" },
                { "si", "ce931b8984766b7cfd981a34709a6a345895c5b59dad4516ed0182ccdf1f3672b4f903e32ad3a56a6d8820fa408f36a571170a1af3b1de53aaa2678c95b72371" },
                { "sk", "3273db416fcdf84abd87bbc68a8a20f610d033598a03eff7ae265feb1f97bfbfa5cdd813d77296e8ea3e19dba594a7cf3ee7aef80ad6a4a81c2c27d1cf20560c" },
                { "sl", "4ded885b8d6bfc24c50ef42c9052ed1b2ab5a265ccc51b6c1c246c7ae11eebf4a837ac5462309e85252599324ad910b602e13c3e78233c2ad4ceab82ad02d387" },
                { "son", "02d72108f1713dcda8a06c5ee5eecd955227dea3c13abb578288dd3804f42dc76af88667270b684830cb93794f0d83b601c2b6a6526d2bc6c659a1a8d316e673" },
                { "sq", "4ee683140a7d6d79cc88121d694858eec96a7ed7c82d8e27be015e036783b2964db2f99590d114358c6020c11dd4e5aecf98d06cfc1b3d9f52d5cde0d6987f1e" },
                { "sr", "7b5a68b74439c03922320f890c5b57040666b877eeff2ca133ee0194abe4cde8e1b25b6a5d8bc44fc2d243e6ddee4c63db229e7ef9de390c8ed735470d11b893" },
                { "sv-SE", "4beb0dfba3228b8689a45f4d93654de49291ebf65e967189e9f1d7a0ef2af76ce150c6a73a59a526ecf622b84497fa0112de544d6de1c1c0223ff8788a8c8880" },
                { "szl", "6ffb3e942890f764ce54e8a3ca642662446508299591edace093b0ddb02b2489d3b193e8499d143694de58e662a6b014f53873a7285c7d3029e0c5f09ba4749b" },
                { "ta", "94a404440e52eeeda6f0eec5acd47a5c0e30d5453e80767181fbb65191cf5bb85dce5349aa77565063c6e52198fb1c37a12f9b5ae53aa0aeea4941b84f487719" },
                { "te", "a5a5bce94342c3c741c21131ccb7d52ad8329973899b1423f620ad0d71adba2adf8b7e2ac1d213c11a2f4c921c8566c830f5c1de92010bd153086314203d135a" },
                { "th", "0586ade71d03eaa3a00a627a2947b0aaaa1e8ba78162143c3f84064d779dd0588c18501aa1df75cf2284ed5dadd72c12f70a4f6cbae1447641cb03f88f0f269a" },
                { "tl", "d239a906c00043c12d2e49b2f6dd3352f3068713b11299673aa9ea3968bb3ff610138e6b1343bf29aa18df786926be0159dc3411ee0d40820c22e82eaad3b3b9" },
                { "tr", "b98efbdf6075aff51d66dfba5a801258177e6704e438195a8bb4e0b7ddd242b80cb1e904c36766f6ce49dafa9e7fd589b4afcf5b4a41c86b76c741da1d03ebc0" },
                { "trs", "7605556a75c35c09632015cc9b98003d408c41d9eaabc72d432e35a91e50ce5f418a0734c9b01a9dc8618a29aab9e98b4f4ace30003d80d462cc57374308be73" },
                { "uk", "4f5c9b500a5814698bbe5534653c2e30201ca36d99ca95aa3804731230a444f41a40ec053a77b2b1d802db296d5fb22c1f20708d13b463da911a0198ef04e082" },
                { "ur", "86cfc1360451f941bf479deee198852981477973d47267f5540ad2cb2ecdd4c73b7367756500c2f5b8face7250e3ad2974b9f35c7fea08032ef6ac422768baad" },
                { "uz", "ed30c5970736d080f6e83c702fbf61dbde586143461b9e78a62fa9a0a61466c38cc66e86f90efa2a8388cd06b7e4508e4572c8f3ad95a206716c7aa37d6593bf" },
                { "vi", "267294546933e8499f17f8de657d80881ff6cf62e57524d889de932b11b6d3188b88a942a0170d3c994831d00f5ea1d322fa63c837553ece59c7132eb4048d63" },
                { "xh", "7ee706d1d958f474b4127931fb8e31dd8a3ba7e72ec04254eecb454bf1e5fd432385cd336d34dc945d27968d6521c44e43c6d1e36ce6e7611276337f7fed0e01" },
                { "zh-CN", "f40e5a349f815e0e787dc7dd0688e74e7c33a5c85c54be40417644ad9aef97d601a60950aea89f5add487fcadf45753f2e3ead3197f0f13050d6aade8b5c40b9" },
                { "zh-TW", "35bc17acbed87b2613ab4c48a42b724cffe4f3fac04d6ea69496a1781b1f735bb27e65c3588362c891914677137d8a3ea365c5401a8205a712414beab9730bac" }
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
        public string determineNewestVersion()
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
