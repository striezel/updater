/*
    This file is part of the updater command line interface.
    Copyright (C) 2017 - 2025  Dirk Stolle

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
        private const string currentVersion = "147.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/147.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9d51a75a6eecdea200459f1c2e1aab6ce76f5321a6bb41a2ed8bc3130d4f7f38b3a884a29c776824bece04e0dcc7321bda7afd446e0ed67eb9e590c5d53d3ebc" },
                { "af", "a8b8af5af7d7b8014703787c315152b7ef66748f5982f8aa6a0fa21a10b7b38576afbd0e1afc3d940652e648200c66aac59458e81df4818771fedd7f81f99d91" },
                { "an", "6dad822d2e108be9e2632c00ed9a50e9cff04fa947b8cba3c50d2c748a595b82178d2b94d103a4b042ecc40da95db83f462005fdddc7b982c1815d7b56ba8875" },
                { "ar", "540c16beee2074966ef5d8299ed4cb0729759f7f5a7e9c75b7243ad3e9ca5aa4218bfcbb217e45aa2d836a8bb9c02343cd4c9ed3599093e9f51c66bb239344f2" },
                { "ast", "3662f142c3de81cb9abf2f54d14831a830949b013b646feef7373ed0a4ab7f6feffc95b19ba06d6510b6e4f8e99a8475fbaa739e8dfb1b039919dc812b014667" },
                { "az", "4876055b3cf5e520539c53a024965a8bc2edc7deb990d336b4f961deffb8dfd1b816554a8a88f3c703e5e86affa09652384c7ded161da916501cbf015d1be876" },
                { "be", "4905d14c1e24c4ae0f6d1624e984ba2b9fbb3be4df06b863ac3b9cfce3042212f3654a219c6c1a771f0366407d786d266833e578c19fd1c6717c8fa3f583c433" },
                { "bg", "75eb3f3ddf096e097a65f4576cec2134cfc4bce326663f70a9227c6e68f6013b77b8979f2818b04425b781a7756f8f607efb6ed08273b844cee58717f976ec70" },
                { "bn", "0504db90fade921d7483ebea5e4317b48e35512c9906120e11660472eb1e1e3d096d50e33561c0eea3e60e0e98fefc365e9f8b406244c2911836547a58eff8a7" },
                { "br", "5e6aec25e037c5b239096f3f8e4f2b688d4e118c1184e05b211fd361de6270d886a09ea4ece3f4d51b0d7be36a767579312ca0d9312362184b2e274f48dbe6bb" },
                { "bs", "72e3aa0f0ae60cd71f108a3e063efbae6cf3c188b5baff1b255e03cddf9a9c1159f22c3535d7c103c0cadd661d386ed5275cac0b994ae59cb95f389b77a47ed6" },
                { "ca", "3b18ebdf3d32ba55771d849a148700abfcbc323cb338776b73bb94e9875c4871eb638fa654b3e8d2b0e0162e8d4af0f7b847db88e4917223e5c917df4fda8f75" },
                { "cak", "9a8b808da2e0dff79941b39b96c61e1c980ca81c08490ced79125cf8e9d197392ade89fad7ffb331f1a959035f9e224fecb89079f600740e2dea7560e04bf601" },
                { "cs", "efb5b13040b313e0ad0806b165a1220b55524f6f8f7f1bc3ca137cdba0d08ea5380cb57121878991b38d5ebc689158d40e0677af2b187f28edab30139e3c2e27" },
                { "cy", "326dd1f3036ed1a04eb0e737bb9c8fcb3405d02240aab6858d1c36071a3e8a1bc4ab111038976ed6fe2b6247277a2e953c954073f8a8d509442bd8b6ca0832e8" },
                { "da", "050df52e0fb69cbc84d719f6465f805deb62bf8e78f8125ebb3bd810ecf5ef821e40550812c56137be50ac865b46275e1fcbed4ad7943d207a63e78007a7bae3" },
                { "de", "0168143f790c0fba89beb5047ea94043ff9b121095b0ed9f291d596c4d8f0fa9fc6a1797f463542e037e35697d66b5d002ec89cd709e37f7e8dbf4b585ac94ba" },
                { "dsb", "2cf77175dbc9067190a7915a498ac53a4daa6a8b51894fca4fdc25cbc318439456ba0bd122ec556251e9c9e707b73d65e7959c31e033e87a219b7167cde3ac5c" },
                { "el", "6ba340bac98189e240893eeb5470f069dd280c0cfac7d7f2e7ee73b6595c87c3632aa4b737c3be42419a4779f13b84c6ca5d72e6194ce080aafcd7fdc831f47a" },
                { "en-CA", "787824594a34c5f4d7f96f2bf132241a6816ba305a9de1983655a5c02562f11c2657eb93eb6a2d46b5ff8d3aff1d1f384b9910fa0fd0bb803fce6a85141d8257" },
                { "en-GB", "dd9afe2a806722b536e2e935cfa3c6fe920c916649cf29ecfb1eb80b36301a39f5a6bc96a2109911bdb05217c01cd2066e68dd03465544180346b5c26be77859" },
                { "en-US", "73a4c87670c7775e8d6f1f1e66ab4b3d760e3b62ebbcd0de4dc8348e1860a66392dc4b997b57c3a6fdd6384712c1535e755dc952a62a4c17689ea67452624473" },
                { "eo", "5cdba1013d1e52fbf761f64159ba5be06d3e9310ea716a3beeee21418e33bd1b487aafa4acede5bb07d73f807a0338f326d9a0c8b32ef368589d0401a5d5f357" },
                { "es-AR", "43c5518d62d368968c5886692f38c8d72518b2f6c62fa2a26a04b88448c66e38bf47e85f6e017a3cdd6d92f85105340ba10cecb5867cab63807ca4a237c56549" },
                { "es-CL", "b69e7d79d8ee233f09bc8fe77054a90a642f50762b41216a7ca45e43c3c2f9e1635a36e562f671edf5287a83aa583c2747b894d4078a4ce207b2422787cb97ed" },
                { "es-ES", "10b655242c540a347dc3f001f39730410a0fb6831ed2fa425ce8d2a21ad04a7bc891aa2f615b48f2d2f3f80929ddfd91ddb802c653b17a6a8a3d8e14a791d039" },
                { "es-MX", "1c4a28c915e66f2726b31130a792c80782c6a6772dffe6fb0527aa921dc4f8d4ee562f39a8675004d98c375925e8ad3b053f0fa0c99d2e4889f8bf43e07335ff" },
                { "et", "4e579fec34cd6f50498b2ed4cc811590e879996874511a4a47b629dd07929e8eb338c714425bc1ec728428c86417b0465eea50aaec8426481aceb86697d38182" },
                { "eu", "065eeadcf2120a85a697facade628d757edb1b6c37b7a94da75d9163cdf2fee661046c98d46f3fa5e718f06c933ebe2124994a5e373d97850b76c7792a01a87c" },
                { "fa", "536c84c79862f3127ffa5064bd1d0b346d941c3972a1b103a5d2f69d65b2742b6e7b81a1e00d4f116dfc2dca3b81d7e3a5d75da8345cd7ba973089acc3d76517" },
                { "ff", "2e18404cd4f2be658f3166f032ab037a6c9e5925db24977d86c90924ea1beeeb058927e263e14a3f4829e11b0d10d9a4a294c6a8300a7c167106df61e19c3adf" },
                { "fi", "0ecab7286f2067ddf928de8f67f7459674a9f1b5650b0d54743567d0093831c27ae4e4a32a65441c22ec2ed00fcc21ca460c447ac3ce428c874d041bb6181ef6" },
                { "fr", "7ca549e4f7a182a153466da61f8e0f8a5c3014e9ac7e6e152ffa4c5b3c0e5f8b309283e93e456fb334207c01e4eea5302108a6d5cb219935600779fc5edf21d8" },
                { "fur", "9cf06a9571aad4a78e78d9b3a8fd489f0057653736b02f3c5aac140d476f301d4fba543c621e758c32332d1c69016573a47058528b99f2e54625afa76bebf0fb" },
                { "fy-NL", "6a062f502b4f59e6565cfcc864a25721b1aa407ded899865fd8f42fb976fd4ea89844f1ab8d90e8c9bbfedc3a934885bd41bc440379c850bcf7b00508a09e0a2" },
                { "ga-IE", "aaf0f7a68bb14a4a97cd6b07d2ba1821a287b3316cfb7a58779aec29ae4ee022d1f9ba6b74d8e980af5b45d1fc2a500275355f27002dc1c4bc7693205b472cea" },
                { "gd", "2ca23103e62cf998308f266dfa8b233eac620d3689bfb5ecc2c1374df023e6ed833955af74bf4ffe6483a87ccc87445fda47ebf94693a21e730f65493adce418" },
                { "gl", "b1bca70e7d754a1526189788ed79508b053716e83c38e3735e85b0884e4dc072771fcc332dc8d96c42a9527706e6ef2a5238a76ad809450293d18d78c0a82826" },
                { "gn", "12c876d051ce0c765cbe1510a9a8fafac796396105ff1ae42e4f7338bb41812f5334d7b3b020538e6074a95b0653c1723808556ad9d3c8e01394a4add8ca03e3" },
                { "gu-IN", "eb2d625b16ab0d7f7c1d2e72cf58cf8325d1f9eb914cfffc0a74825d44ac42520f548269334436b3bf77f9b97e56831ff27c489c52b8f42dc9fb911e98d30583" },
                { "he", "3650efb23becda2eae570446ecc2b326ff983569d695ce02fcdfa5edfb03cd119b2bd65624784244913a2abf773715fb526df63fd0037d775db39770812487f9" },
                { "hi-IN", "4648cf5cebcb6e49fdae90eaa1b5e202736e63404cfcc15ed756b97d0bafd7e6f7b79fa69e0df6044b08838c732e2d416ceea1108066c09e7c3bb61219e654bc" },
                { "hr", "712c5bf92501aaf260af4653ede2119855884883f8b590041487ce320b143a7d9c34b56631bb5da0341d40212cb5c8b682d92c0ba425ad25ceee825109a364d3" },
                { "hsb", "bb5a0ce78acdb00ebff0f9e2e087b8cfca8a5a565b73c1e30f4dfa38fda386d505b150148da5deebf6745aa33bdb6a6b1ed974edd6669fa48d5d44999688d257" },
                { "hu", "78754e5c5915a17bc34b1134e4713023ed1859be15246e1c946cb817ef6cd40240420e97cb1c3fdcde6b95b50037db6059a67c38509768d055158c6bb19b1931" },
                { "hy-AM", "fd2f116b75a87070f15a9c83feaefb78b11f122b8d88cc39fe64e9fa357420238976c3aa360533ecb7ec9db40e98f1d85a3aa081c44f03c1ed9aa93ee231554c" },
                { "ia", "679b006b70d504819ea033e6d57c980dc496353e93427e4aa1416b45d2c04d4ddfe26d773f445ebec610c43291693041e45dfa7f377e8f4edf8d4663e849e919" },
                { "id", "64809e9326b04b719a11110a3c4568ff04d4b1dd84b2da955a0b69b4de4ea978efe5426f7158f30baa6458516782a1cfac1446058ce73ee8671a1fee760283ca" },
                { "is", "c22a3b2f508d0a359dbbbca0a7be9a410c4346774cefd08938f30d8b5d33537638318d5f3f86b001bc4f351a4d2760967b34479de46822fec9a811504cf3ff95" },
                { "it", "99e99f47f512deb306334d208f9308edf2f1c6813eb6d224ec6c0e1ce04d8075f289b76bcebf9b762a71534ef3b4f5de881ca290caec79b92fe2a57ab733d271" },
                { "ja", "8bb8374df80c6a017dc12e751922afa454a990c697cf0f4b86eacd5bd7b620dd5aaae3bee728d5b774b2e58418708501bd419092d3c3674128913d8823259df6" },
                { "ka", "2983010b0952d0606d7593932c821366fbc5140d9d4a1bd0206649dbe54c22429bce72baad0ee0762ed6bc8e76b20f5b2d0372687c63b942cd92d2927964db83" },
                { "kab", "ed48b9abd3c0eab3b2116ae2d47f0088ec95d6f984bbb408c59b0c50793730ebef96d48a1e2bad4241bd6bf2b22455808affe0ba5bce4708b314143f2eb4116c" },
                { "kk", "ccee9ad50d39ce8b791e4264325718d2ce05885f7bd67b4c480bf0d157d299d040a80d443364c61c27f42bd5d7cedf24afa82601ec2eb283f919b1f264e13300" },
                { "km", "561cc844a831d3f6d26ed8b08e3e7ccf4aa0b5c78035aec1e38242fd75d78eed4e815825c2fc385af80596d13ee779f4bf28c067999f4043c94a10568a48f73e" },
                { "kn", "90edb081a3c8c203514a0e1e2cafe867b4f15fdc191b6a2753e32fa88c32fd36a08e428b839b01dd57f8443dbaffcbddf9291c76241970969647e80ba7146090" },
                { "ko", "14178a14975669638af29d70b94346aca6f5e485173e6f81bffef23a9512cc74cccca18fe01f623eb3e8bc60441acc6c1d323ed60ab598914cd4cbe2051b88bc" },
                { "lij", "0c63d28e8d0122d5a5b5754b7e624bfb77adc45f878d11c0e43c2f75255794931bcffe5d4eb79b934a5188528c699cac76468f47e1e810db866023824b88c94c" },
                { "lt", "d0e22ab832d27cb62b476fcafa723536dedfa8a8a715fcc80f4065aed2ee8de9a019602153f971627c0c8ea4859893b81caaddb7d3252af5b4be05a03245360f" },
                { "lv", "c85f4768bb9dc5499bf63cf0f7e9319bfe948c1c71b390ec3c2fe9c4b47b57d317a43ed2d3652b6a1cb708e2514269570766c0e04709f7f2ef29943e4bd95e70" },
                { "mk", "3cc1dc50974dcc102a151f6ef65a7dfb2ff5ee2d915e10be826636236262f19c5e82bbcc7dd97363e6e314760734839b8d2624a0d02e3a7b965d65b8b8c1aa24" },
                { "mr", "26a90a2a707fa9ad84255096e804d83bf11ee63cacb90bbb78091433b543ef9a61a75812678a8cd7efecb7c36bca19eef72a778ec3ddf9d49b29b25db588c273" },
                { "ms", "81cf59b3322741fb701c40d008bfb4540ba3c1e6b3903c5e1ce59636137615ca3d30488d221af5239b0658298e1fde3d39a609cd224babf6e53712873f2069d3" },
                { "my", "b66dc19fed5607d8c50013bd7fe756bc27e22d848b40fc0c5e808545f2a0a49844efa66b5ba87819ab20ea0a42241aa988239921b1a91223479c6c99006a6b84" },
                { "nb-NO", "d4ba327ab63b92f3acd8f701c37795dbfecd077b2d15c60d2ce4dcf99a8060cd19504ba3edba34458f21cf85d66f73b7a47f89a97f20583d496fad5f5f37983c" },
                { "ne-NP", "bcea63b7822acc8b25ad24a96066ab437ded864601d4b64ff8eaca300917c66c94d30817c4b9fdc951f2c68d3e3daac6c59433dd7e23c73ac1b3d6ce04f7c67c" },
                { "nl", "9b3d55cf00db02bd5de395ae5f31b4d42a8d10340b270360901821785fbc77abe65f017179106591cbf06f37ce00172f5aeab073ebca62f1d10feb8ca07cc3ca" },
                { "nn-NO", "b5e01543e815ed33987fa822a2e918054efe9315bfe4ab93ea746021c1e75cca82179dbc7ed1dd593c25ea089828f3797bfef114767c0f0ab023fc86372b8954" },
                { "oc", "dafae55b72c81384c86d835c099ad6078e4308da312142645a3372419b88e7d9dd6debf5015009dad72b235c40f70ea874803d55e75e37141ffded2430db1e9e" },
                { "pa-IN", "21d6e350dff707a0e8b8e906a1ef7ca9c5181433dc743f7797cd62f42961bd281836325b0ce72f9f79a87f675c5ddffa96251360b4099a9ff058c420053f3237" },
                { "pl", "91302bf01dcf7cad0ebc719108778b9db7ff20b05d0def609f4ab451cebe7f1d7f42d8c5763f528f466f6abdb41cd18fb19ac362924dac6cdf7b16ce85ec747d" },
                { "pt-BR", "d60ef3c4b79febe44e88eb8300fdbbf59e91987246f2846126a4354a24fa6b5edfc6f1104ea8c093a38e56af2c628b8939caa2402a2d63bc0f42e3712ea6f6cf" },
                { "pt-PT", "318d61dca4db91a2ee64b2b08d833f6f8841d4c28bc0822ba25420f4b7bce81b526cd296f4a93322dde962a576cd0a2ab2e03de9e46ca634c251407d32b8dff0" },
                { "rm", "26b1135d953eabb04c31404c5c7afffe49be5199b875f76c4fe3f62afe914cee9fa95b457bcd802899de76888c00e992f742e29a7636909d0ad618bd4be0d570" },
                { "ro", "2f52dffdf40cf8997714481618c5ebcf5a4fc6d8b7e277a3d97e40fb6b5a1806ce7887a135eae35eff16a340eeac8836a9c1d295b7d8e232b2685f709862a11c" },
                { "ru", "7ee5dee119c9c96bfa1f4b9e8b55be7055903af211bfe520b026b5d96b09eab4ba4b7cb5ad45543ca34571cd45ee63837b2e753a75bbb092aaee321bfff4d4fd" },
                { "sat", "bc7a60800d93b3e7f5d179122fe29dfdf401685baa7131eb582251d996c27c2fcbe9fd894c32a964d4dbb796b3e8e147349a7b8e32548c67b6e2e440dc579754" },
                { "sc", "05ea6e87e8539b9c65c35abdc763483b7286d6cf0dca384d6e092992f58a87c01e0951c553b1f9e466e6a39175f6f7c35eaefb906c78a1ca9a38976d01affe3d" },
                { "sco", "0f8bcf06bb837d7beebc001dae522e0f423941ab5d3820c856febb5364c2d1528a06d1abe9e06054d74b593528103bedae96e705a1e3aada46092785a26fe3ec" },
                { "si", "f4a29044c05ca4c2b2b363a102c135a9810c5ec6359113f90c5227a5642eb210b58521f3c705eb2880a74c2fb05e7b6a1e15c5c741eddabfe6a062e8d76b4845" },
                { "sk", "01126227f4db79bc49f8011aea51378872cc9cc65ba972a4526aeea57f410b31123bbb74efc742123d779b12aada18563ddcb7969e86ba2b6f77b26e5f68c2c9" },
                { "skr", "7c0b9e88dde98275d1907f809b415e501772b9be00258a7fbd88b449cea081cddf266f81a36a6a639221b1ffe274cbc8d7551b50cac882df4704fd3ce0a05c14" },
                { "sl", "74d656025c04390bc0638bbd477c9c2a5c71325184ec85eb0b17bec4ebbaef31e1e21856d8feba4fc091a35f73f474523372cefeebe0830f7118ae511fff729f" },
                { "son", "d4dcc13eb3f65f70f59853d0824a53ba2c98218b69b813a6001e24c87e1209cb27ee8ba4b0bc09647ce9702ff46f036e3af090ea66413ee68abacfdb1b672605" },
                { "sq", "cc5001621299c484e721889682f84e75b41c855b9558bed65b06c172780d55eda644a49ff1d935226ff70b8a28638a791591512299be2dd1a5c97110411f72a4" },
                { "sr", "7c598874f2db83575502411e9db8502c9e2e52103aa9a1d54e7eb337a7a832f9df6d42dcf8ae6764bac71aa8d260f2535b33384ff0377e8f7fadecc8e4026164" },
                { "sv-SE", "3524394fb9151e6d80d7a154607f5176399829a47eb8ec5f76e68574df8b2e27914ac5e8b4ebf082ece5b749bfae7958a1db6cf02f1fd56280bcdb610cdda4a0" },
                { "szl", "3a5834f7bff3766400d2cf443926962899d947d9e5d2cde3a28680af58d93252193b2aaa3c14b42c5ad7d770ae54ee5c415805ac489e29e37dc701a4cb8945cd" },
                { "ta", "52213e4c61a9f0d2d330358b11816572e6852c152b90ae5d9eed27f279e517eee38d2d63f6deab4612c1baa3349beb95bafa343ff1f635320215d10dcb3c8c7d" },
                { "te", "0419552ff8e11380f2fdd6a34f3fe8ada060c4c008c4a1787d15d4b698f7bd3e01ee5e49b1ddf926694011d84d4da8d6dce401c703eeafcb7903942f81f5fb70" },
                { "tg", "2894a66eda194fea0ecf8745ff4511564dc3c16ad34618b0e7de1a2178326dabf5773531649b9862ca90a3fe6b8cf6d9d91cdc2de5d107aaa3721581fb7b2242" },
                { "th", "b9a79bbdd04b2e05645a00143100267e2e2f63d9b2c332b5b35d7a7c829e211919672725e2d9bf87a5431c4a0aaf5931a6eee4dc0178ba6c8cdfccbb7638786f" },
                { "tl", "7587878b0c4eaccd8f4f657081cd75a22f93836e2e63c439185da8a12e204c7074f8ca1be70e19df5902f0e5ce981b6e406ff82d943e595ed7be074c7ae1c90d" },
                { "tr", "1d3ee174cfa2fa4a62c250dc428deb20ceb5888d7a0686da23227140ecfe56f04047ce4102c03cf051d991b41080cf3a3d676611a9f9036bebccc72af89efdde" },
                { "trs", "310d7a8a5b61ae5782ecb917defae23ca3aa528ad8b0d8bb8033d7e8b42acc81c12d74a04c761d96649be2cbb2e953821c40348bf71e5447d5d40d02d6e52eb1" },
                { "uk", "6a05d36a7719227aa72513abbfee469359cba411a1e9695e86efa899e004e30fdb0430179717446611ef8464cf1e04ba7fd5e21cb660771a0cd2eca966147979" },
                { "ur", "acfbdbe1878284c28c98acfd7b1cd8479b6df619470c36bab6e3e0e6830f04411349605ec6b03cccf1cb286b9ab2b1dcf0dd795618f00d86b438201c23b1fc17" },
                { "uz", "a8cd687ef21af0f209be1fd3433d5bedc0985065772ae9400c6e69aa6cbc04d961e7f40a2009a2fb51edf907609749b076c89bacd6711a9eb3dec286dbb961c0" },
                { "vi", "810c19406a79be022264cdf6ac7301d5e8243e8198dbdffea94ecaaeb0bdd8ef09e16feb8bea4c1e906c19e0f26097a91fcdbf1aa1237085ae1192d551575fb3" },
                { "xh", "5a949771c197c2a5ff7e9a2f2d3db978224a62b6168fa279c2dfdd96ad273644490ed653a657e1e372248431b4c6172cdb2f45d0da3a05f068826d02dde521f9" },
                { "zh-CN", "eaa14b7cb37d73390345630204cf3b713cb4df290629270e00417050030d6fc29e3cd44f596a51a4dd282db1681440f53290af1f7073e7c5e6162e6f4c1d95b9" },
                { "zh-TW", "1f5cd1ed5c03300e0c03866c5163bf8a45a3dd91c978a01466d0882ad55f0ab03fbfdbff2066d060e744b5b2b92634609e59d29c40920326f36497d5a03ef295" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/147.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b5d98f55694756a3f42d1e8e5f4431ac30f10c879e4d877839bef81be8e3cb4adc105bc7afa2ab360f13daf3776f556c1fc9830b2be5b95232ad83abc97ba5d9" },
                { "af", "98014bc88cb3104a93efef25913be7de3d37915864bda0e8a93d2047939d6cb28973c033a86edf8ff14750a3197ed77694a5d8132fb942f6c0bceea9d3357c27" },
                { "an", "560876b2454e69516077877da9738aaef4dd23ce035722ab9586cbc39add91788f44ff14aefe22c860ea72af3ea63f55e6e5e3ac02fd37d98bcbdd83b7d0142b" },
                { "ar", "82d6b027548207085a5adee2a33637192c814a16fe7b7c2c20133338d944d990a832b22574282f2fcb0749fce14c67e42212707697ec902d20039847115cbc65" },
                { "ast", "c71315d4c3174060fcbbce138ee85753f24ebce7a7609de0574f2c236294bcb44da352afff15faa6ee465987e85c64e151e0bc0f396eca4b50bebc991cc7f6b5" },
                { "az", "6918abc6171a4188a576491cc7e3efa1ebf35e7c98cd8edeccf1244f95375cf772077c12501ef92164509ac4b14558e98f2754a53a4d4c85f2e099ea148a4f99" },
                { "be", "46a01900a0e15ca0e465422cf62c300192430871d6c91411a977c37b7458d59a4debfb1a9c538c106be6c9604a2d034367b9833e3a08a5611d2ee8d4b0cdc55e" },
                { "bg", "5e3708a37c478f8bbc458c164e366f39fe10db8e454ed76816c9fa5415334eeb79daeffd93b28698761904b82e4c0a86422672eaeb30ebef235b4b5189fa9d32" },
                { "bn", "9a6da1358a0d659a12761b7df83a4ee2f9e654ce8d125a2c0b5cd27783a86351cd09880b24567663c5125436f08cbb44467f159852092d95a31c8d9be3a5e1fa" },
                { "br", "801f9be8d8b5dab2165c77a0c00b31a01c2cba34225868cd452bfd1af8e63b864650fc4ab32100bb8e26d38b00a25f88129778b892be9d74ebaad383fa456a70" },
                { "bs", "12df83e7801f2b003f209a9ddc3a68eac9751890179ceae6806280d8e8aafa5606d03662c447befd0240457642e3586a89c50a6a84dd880e58e22010d0936984" },
                { "ca", "7caf9d69df3edcaaf11bca0a380cb88444829546414fbf90f9afe2bdd42e8ed95415fb07cf9e600a00c6c78f80e546f285b622806a785cd46360a4b410657467" },
                { "cak", "ef0d6b6fc0b4c18bb16d524105c930b0c3ba163cca3bf85440c3cf2e461b6cc5ae699c953e0e0b2c3f1c57bab399aece6a839bb26ef6df5a389fae9e8911c773" },
                { "cs", "faa8823f655564cd842beee74159b83084bae79b3fd63a3f147a214515b2d949bd3b0d0851241024d2791f64ca03fd17c2b73689aa18b236ac4707fc1c9b3931" },
                { "cy", "2891f1c342e5df2f07845b9a07a326a120fb6ce37e0c73f9af8e9fd29f50552768996e8101dd398255a3305ce9d58a43969ec0fd95529b7df7dd4a75efb31374" },
                { "da", "c35bbe8642e136d2e3e4e564c2e8c98e79ac8e8652f6f8360772d11d47d61f512210630ce665fb3561cb0e1283730e358de09fbb08968b239cf26bf3d0e0c1de" },
                { "de", "b93a6723c7521b2b6a594ababca53b6596f9f3b6bff89b13f3711f26d476b69ffbc22ad2426731c7c92d667d78336e61ea9efc834306a8ef44d9699873f307a9" },
                { "dsb", "4cd89a8975dc923da15261f40e0d0e315d8b7538ef60e0248d05c4dfaafc8211e8f2f0c46b9ceb6856f4432273be6b4b716e04368c52831e8c6b8f01b7bafe53" },
                { "el", "97eec1b4814f86c8e651690f0a0a2d7397aa20a3177043c4a71dfbcf70bd4383e976e8ecdb2f9ef1efe0865ee31758970c809a1172794d407613360ddbec7c9e" },
                { "en-CA", "2df7a476080fe1f5724f838d3e93152797e028f888e2095aaf22b4500a1497cf27e3d0941939a0165a36d07f9c005af7f4ed8dedea4a70f054ca8515c5cb789a" },
                { "en-GB", "41d0a12253bdc3def6cac2c7e2bb46890e562bd7d0646976a39f3388362e13452cf177de95f77f59a66eec91edd154f6be6b2cdf159306e8a5c2a2ae52967c6c" },
                { "en-US", "63f0d155b9274baf1c5dff513c0bec28d108b7b59030e24fb52ad182b68c898c1e3ed3e8c860d6554f4e31f6161c8789b36577975d0de1211066c90abb1624f2" },
                { "eo", "bfa0c638eaae10e601621ca2533a599298dd4062ccae022d4ef3b2029be2c3b8aca85b207e6eccc0e42db88e511b36362be3f110557d6846fbcc75ee6d4d4963" },
                { "es-AR", "9e11106b761a8aa8c511c824e138f6b8af84041e76d923b369246f0a22392bec9d0bdcbba6c16f4c5b4225d9c69f97175bd1c2c65bb163bef2aa38dba22fcd71" },
                { "es-CL", "e5a32df4b11003349655ee6d807d0ab01c6e0cb821436f9f8082c963eb3353edd978c6f330f35ae9e0bc3d26384e03b09e1f29b1bfec690399cea96cf54c4ec1" },
                { "es-ES", "065b761e9f4743f7a08ef7a8d3d403e9ba203a615179208fde5902c2cde2323a50a1a203e517256f251d555bdbf11805021606ff07b507566c3f8d306f34c632" },
                { "es-MX", "dcf0e188540fb461a770da886f88967836e5339b14e3dacef977b452001584d60b67c8edc6aeefd2499e8d4d9ed82e67d882e316a842b0692b2f0b43a28dbd1c" },
                { "et", "95f79c93efbd5d3d5e7f9e257fa0ce57c30c17e470b904271053929553f9d011d95d5aede7af401e3616b4e3f0271392c083d4a7ead78aa467910787bf77c5b0" },
                { "eu", "25ddf3d066e6fb96dfe460c24d3eb599c5a7814563a451be02e196ae49495ae0c290bddb061d77bd60a47a898fcfffd6cfc743c5648efba377eff0c5ebd31ef5" },
                { "fa", "b0c86c037d3df9c856b1833b44717edf4447324960ed8ac28115620229190d9d7c53c36884ecb77b9d1d6a8e214227192a5e47f7e5d8e4165ce0893487762a15" },
                { "ff", "eb2a30030a475d0ee3bef2b2f2e777fdfa991110d9e8fc2cfbbc847b334277faecc181010189a9fb930661e78a923800dc8f0c48a2c768e09f4c5df780c74688" },
                { "fi", "3adc5424be7936b5590ecdcf972332756ecf1086e6dd4043647eff39dda50899675bdf1f0f9cd1298de53939bbfe73e583de86b723dac299af69aa37b3fbb762" },
                { "fr", "80b6ee156f2236aec8e9bb2689c03ac49b4efc183a0fd9b960d459694e1d9d8fe1ad8cec06bcc5e718244ec48393943f289c8abd63e215ffd2b27a1bca100fbd" },
                { "fur", "b90ecbf22dd42b75bd0855247634423be440065c5cdfd43ec8de0c297be51042dfa1c4e533e46c1cb1957d4c81bab7f89d8da3b09a9f3d9d8d98be53879ede67" },
                { "fy-NL", "f9c77fc24f4140b303f8c2d68ffcf47c9c50e10eaa4cc6cfd9995a1f1c46300bd487864981c03387a67b634cf73ee58f6adf2d9cea41d890343834a8aa8fc8c5" },
                { "ga-IE", "604955a76483d672cff36befa34467601cd99311ba2758371d429e6aade306161122de4468497491be0f07e2ae03bb65e1e8f1c9a8bc7af06e43a5184555268f" },
                { "gd", "ad426d3101266b358c026e2ff31295d7b397cd413bdc6d80fa781fcd833d31808b0d07f38ac3cdb2e17ec88600bf76566ade5a4eaecdd4035325d29271dd1595" },
                { "gl", "7b878e4b27795977bbcfcc7ae2ccf002ffaa810d9756dc6db778233a722588c2b5497f006bd7c2b05b5c475fa5539fde99a2cfd80be9b5fa7438962a0d20d740" },
                { "gn", "3dfdc5f30bbed361cc9353cea789e5708bea68eadc71cbf2fa7f9fab9197b8ccda864e71a09ef69ab1fb98f88e34018670f0628a4fcc3f58860191318105061a" },
                { "gu-IN", "f45c9cf97307196f8645043eb4c13a0371c156101198047f49b9992013577db5043a71afaf448ec6c19caa262ef27c432071e3b816f5d446d00718b000aacb61" },
                { "he", "526d189d14722e6fb180c4a867c30ac7de24f5a54f9d5ecaf6e299cc68910e4d2fd2cb69c518c2345ed2ee37ec3bb6b545b2cb0db4471ca758245d96282e7969" },
                { "hi-IN", "0902b0d12d59a7220c818812487ac4596860b343d01fc08c23fb7349caf50d47672834e574550f7c5085afe170859019d24d7bc9fa8b9373418cea17bf21b929" },
                { "hr", "e4b3e0da3dca8f14e6994fd40956481c1bc6b70d106e55f0fd3a6752e4daafa41154424cf5a40bc3926f055764dfbaf06b0bcade63dd73fbae8b7eb39f00310b" },
                { "hsb", "a2c996adb61f311caa2c6d62304d272efb752812400f88714c81435829b78ce8380d2e76a5320c7139e4fceeca4aed031ee90e19a2c440a9e7ca6b054506b9b1" },
                { "hu", "3d8a69dbef92ac16758ec6a6ba4c09a3edac7b5482f4f14f0a1da51a7f4214c4b7851c222889b2e6a2b179b3c97a001b2ee2fa303c62096421764ffbdfa2bb83" },
                { "hy-AM", "b1ab19010638b6d6ce7132488245f5dd10abd19ed7e8594fe44c0b5facd9a6fcd4c62fe9b81e9f4ee11a31974a72d475d3a347fd7a050717c92d4fe3dfe4193c" },
                { "ia", "843dcb27e87d2501fd29e9f10c0a436aa93eb444e4a26dca5d04a331077ff46f18c0c89f37ad10d0bf0c4edd1dfa68641441c05df25b750b58ba47e2aadba138" },
                { "id", "7f2e40029b8f1717c83f8c1462e056821f17d73920c89ec7bf70afbe56782bf432332823a8bd8f1b9f5b19b5f2124a643ea58bd7077fc00720008fa3e212e3a7" },
                { "is", "d8625612de1db1b8a0347fb8e8484f549b7d6dbd66f57a68b051325faf1d33c69dddaf01b7fc3f69eba1bd7a3bc4a3df32b5a815c91146d9b793b690fa389080" },
                { "it", "106533f76e891ff69ca7e256c8d4f5dd2673aafe24b04b5323d94c1057983c3d3c3292b4a3680ea861feb535277f38fe0d605213658458ff5b0ac32a4224f43b" },
                { "ja", "dc533bb44d1967c6a2a14640dd511c439508c4851970256dec4703679d2689acc74ddc231d36abff4684b79e7aece10434570fad339cd95aaca960ef9f0cbe05" },
                { "ka", "d667f26e74c91a16a21890f0dce5bb23c82b831e90b2b4051f182092cb4e68494e95c8f2d68c8906667e487494312867d6c8f316943d1ae8b614ca59b59258c8" },
                { "kab", "d7b6a6badf5e8fedc4cce035b27e48772cb17fa363f9fce739394b5c559299672b1db17019ba92a62529e4f954ec6ef87ab8b88424d60259cb774b72f7203d7a" },
                { "kk", "27e64d7331e63f4cfe0acad9d9d97fe73a586c82d9c063ad26fe6ffee6447451196e46801bbe17c5511138d9486f431ccbef60156648fe0edca8f5d02b018b1c" },
                { "km", "4383b07423960343671c74d1af353d7c3ee41db5ad4a9145e10ae88100353423458efe82554a8f96ea6126e50abf592e07b20817111b6d1c3b0c77d4e85bc404" },
                { "kn", "7ee1c30dc1f3c410675e1be272272c45f1d129801162de6e513fa9faf27ce255cc3c1754babdc2273afb94a1d2305b70b561064c091096fe1aeb10da5e9af534" },
                { "ko", "062efd0ccf23d2c4810f69c8eda4f1f11b7f9da405b9ddf3f1feea4fd90887540eccf4e264b4689eff25107b0ca690bd63ed7b600bc9b3686a300519b40c12b0" },
                { "lij", "921998ee186b1aa295805f57b6c9f0c0d3d2a079f4fb6588ef35c3d8158ef5c9ef911530d53c3bbaec388659298508cb69ff1bf5a037dfa3c5f3904300aae13e" },
                { "lt", "71aa347b821e1d6cef8966169494a489d7416aad8acc8a31a8e3c817d0560313887981fc9994f9e8cb78fa218a4bd78a085428de2a68f0e2e66b170fbd99f0b4" },
                { "lv", "73029fc3aff191d3a58c3a575f5a021f6bcfb5ec050d6c5c079239db8df49d4216545ad61e259fd5a9dbcb0d410d878e797889f98e5e224f2171ce868b263c01" },
                { "mk", "8252c3b254efcb3e207fc4220fad024bfc70cb73e94ee63bd702d17a1d41d0549f0b47ede754f5fd19f5669bb27ec0aef89cf74114ff5a719df74f5e9de530f1" },
                { "mr", "a010cd50f00aa44e834aaa10d8f1d92bfc4f67d3a6759d821bd3386a7e89ac5bf5b3d5e57f0aac2d258f25a4dfb3bcf060707bb897828b581f522ab62821de25" },
                { "ms", "0061e15669373fb44f47d44b83d3d741fb8f095410ef377875c55ce82a8a5914ff1304b705f67979d675e7b8f1e31dd89cee7057daefe868976e3d6af7d758f5" },
                { "my", "a3948a27e2b59ecb2a8eafba0cc0444aecc5b38fbc8e2c6c6535984f2e4e552630e320bca88527e7e765530d38f55709456515f89c0f591a85e42c344d6585bf" },
                { "nb-NO", "e26de0bd159b5700e0654b830e3823da16a85f5655ef2eab01dc2f165baf618b0b99c0143fd240b891ba2ed8ff0cdf39bc79e3f9ee1c138ad150127526c34a8f" },
                { "ne-NP", "d51a8f5e17db236345d1b69af248f60839b108ec7dff09b2a5b59765b75a1d2c4bd4e573c8ebc88aa687af373cd6477db65749d1a1a824b776dcebb5c911f0bc" },
                { "nl", "922103308a0c12bbfeda7489a7e1033fa35cf63542a97f850f78cce77e8b9be6a9c727e3b21732af6da784976756a3fdff60ebc58c879f140244a91089d74349" },
                { "nn-NO", "9c85472374af5b5b8b694413234ac8a198788d1c1f75a9bfbe04874619b4dae4228e682f9269823a952b77a5940759c7eb9d366f67eccca681ebdb9f9ee949aa" },
                { "oc", "4ffbbeb3bef0d658d3c043d992ebc5852978f4b8ba675627cbbee1f80768826967d510900b2922c1324e22ec8436fc38831b84339433dc5dc41af6f6541f2c7e" },
                { "pa-IN", "98aa94477b24459ea14326d5bb4502821f80af54c2a1ec2ff50d44d3c5406f3c949acc1351caa8b099084ba62ecd537fda7464e64a79e1d09e73808fedee002d" },
                { "pl", "26fcc4f87734b9884b6fb8523e09a02952c9fcc96e139b2cee9423269754887dec0624f5ddc88bfe81810af3597fe46d465d911f12f8121d650531f38f09059b" },
                { "pt-BR", "55482a6886a0f864867a6de60c7b64dfa57ca8d1c4c3d2a04284d419dc955347b53d0672474eff20ec37a2f70cc45f12c41b8b83790893acb0ec8103d6708632" },
                { "pt-PT", "86e5a6571427956daaeaf478ac3b36f5f6ff409be9d60611f6ba418d76ccf624fdaa764908cd52769eed02c9f38ab38a77b1839a76f89b0c9d7d4b0b1a881977" },
                { "rm", "339e7652d9a57c4108c00379659cb56af23b5f451c296be0c727da0b1f250cd1840dd2cb561977fcedeb25876ceff58c286754c9bbd4cc5dcba1c8df8fa87cc4" },
                { "ro", "4fa01112978b3d8907707619cfb649c0217250dfa10748d9a46f27cf5ee56c58c30db00652c7e54a1bb8bef92e38c0db76d991a77e6f22d4007409bb4a91e811" },
                { "ru", "82f3a286acc04c1b6d53e79a3d9ab9a0d0f009644725c0bccd75151589651127da1480de49aff0f0e1a2a38c98451ca198d1c0cab14f6331f1f4637e5bc9fc51" },
                { "sat", "affdecf933fda53b1eb686348aa0285ae1fb9d03471a882180f0f680583d6b2a0dfbaec62c60f36bc4a55d729ec3cb7d295a8c1c2502cbc595c8ec4b5ceb84ef" },
                { "sc", "34ac9107c67c1e1ec002cd0efd64084d71fd35aadc603b7b7011c1922c2f8683e6c776cdc265cf507e3857198cdc7906dd7a799ae672ababfa1538ae12a068c8" },
                { "sco", "1ef8374372d284ba81778da25047a8220eabb83dc7c040358ab123de15a6666f9a31d84ad3e026bb570b44c51edecd1aaa8b93cd4f7de31afc5311eba3905da4" },
                { "si", "e10d1a674d424d1e6f677e404c9f83d75052b1256127777762b08e909279f9314b12b7f0c741b42c446f31636ae5b7cf48bd41df314a9a9d04fd838392f864d0" },
                { "sk", "5c16e36724311532c20f248e9c4e2c2542217bb6bf49a434b48b122a77f1ccc7998e215279c11cf7fc74d13333bd8944c0b0a85fcbdf262ac4759ab52dbb58b9" },
                { "skr", "e4fab8850bf0c0012cdcd6a02fe32bdec39927b8a0eece68c89b2ba28b189d45551acb53f6483b9c366135f8524e46f30a71bd66a74aafd7560505ab96be53b4" },
                { "sl", "c63d980df2057ed7d0a5a152bd013e09d9101833d9218a0880619865e378f2d5d709bc2cea8bb5a892da210773abe037d82dad9e7f7b06c32df373e416ea00de" },
                { "son", "0258f6faaa81af4bd863f6ddde1d027fb650bc579df1cafd982ba18636c893c9522560ca11390a6c9d0589ee00ee4ca96372d2df1bf8ec9c52a10a46770d52ef" },
                { "sq", "b4256e09084eadd6590a77acdd244449778517ba9531fe0965d3cbf98da7eb75cafa35efeb60dc5faaa6493a60aa25b886a16055abce09baf1ae00aab897fca1" },
                { "sr", "8d5e4c89e0aad25142b449798db260eafa7632a1d750ea0e16f51b5d850b44170bfdbace1512739c69811ef111f74d7e550b4575159ff16bb6e09684c926e8df" },
                { "sv-SE", "fb72449356eb6e118a7d8ffb38761881f48abe738f2c1df84c42504544c9a3ae2ef0b2a24eb84bcbc468b806b1007891fec84b46d0238c3b6fd04a6f817f6c93" },
                { "szl", "d1efa711a3a57eebb618c8a3a5043e685ddef1857739e2fbb11bbce80501d1beba27775a9c37724b66a638dc7719926fd625e56a4868fd1e3b85907dc99681bf" },
                { "ta", "b18263ea876b723bbb09bc1c4e3c5d52ebf0e42c787683041c188d344051de395d52aef6f75128c541917e4bc7b4a177ecd59920809960e3e5b0c34693fc7163" },
                { "te", "76de6e78ea0fe5a959b0b9c7c1b12221168718fa26b87cb26212a4f3a33a888430d435d2b0a79da7c854d2b0519a26fff423211d249de1bc8bcfaf6d437815b1" },
                { "tg", "d61573daef662505ac263a815963be9ddcd28209fec4202fd7859615af169d4f29f5b197cacc116769b6730fb0164660176c8a52501831833918148d85e16ec9" },
                { "th", "4f722043c71ba285ab674d86418da57efeaa5ec68d74d68954e28e554ca83adb7b560e67128c6db978d7d2b2c481b71f07aaef1eb73d55db06a3b2a8277485e5" },
                { "tl", "4fafb16a7c94f8e9dbac066a14223f4a8da70ce68e7715a29fdc1ef45b1ebf067165fb3c62868acc8e99f1ea684c0015fea6b8b4fda121024394f0671341f798" },
                { "tr", "8f779bb3e01306dd0ca176a82d15fba2b55f67772a04160a8cd7597a4c09a103e7f43e8f801efe34e91c470d061bb36b789eccf10b2c59f4ef8dbc546088ae5e" },
                { "trs", "28ea4ce39b3fdde43dbed7ab402300d2a1d787b2508fc08547338da1638b7f0e33ee8cedea9e4ec9be37c13a36333c81eb2e8e1a337285da28ac3db1ae0e91fd" },
                { "uk", "70040d98d7d304edf3e427e86ccd66aced5e5bd6fde6f066d65727201f34b36bf5b973b1d4187d06088254f64f81f04b2a12524e38ad979695b860a39f608f5b" },
                { "ur", "a45de0993c95d2b4b54ad35470da23b6cd83c5d4a11fb6766b5676443e26093dbd99d532cf9c892b217d3070b6713e833924918cccb0602e6bfac0ad1369660c" },
                { "uz", "d2d33e96fcbb55a111e2048e1f14386037cd9f74b46cd6581fd7c38809a89c19571334b96b2b63db129e1ed70cfb01beddf83ecbcd81499371711bb07aeff233" },
                { "vi", "396d38f951e21a7f80ec2be22caaca9582ae4640494f4b6090d6be0d3882880d007c513fefece72a2bf175e1d5c107a16f2ccbb786e94e2222ab15b3e9607574" },
                { "xh", "9183e09d05e75c6c4ddad9fe2f3599a1f05dc76c108177e4a89a647aaa23e4e3e975bf51c553f6cf306f888ef54d196c51103494edf4095fef92ca8f37bc40b5" },
                { "zh-CN", "4b13ebaa22cab0e6aed6335b389e7e84bddf5b5b21c347a3a2b95ec67aa8794dda3ab68f9ea5cd16cc3c9776bd96d798953e13759fb028a8a92e1393052e680d" },
                { "zh-TW", "62d285dd6b6b2d8136edb8ddf3bdbbe3aaaa2f015d81dafa66ea50b26f393d3c625cfe001938595b3816bd9103fdb1fd689bdb532a2741e0b85b6a8ec19dd825" }
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
