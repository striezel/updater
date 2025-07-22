/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
using updater.versions;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "128.13.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit) || !d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "bf249493df423e4567ebc7945e0eae811ad56e7bc2448890eb7287b5100e107e798484f4c235c03b3c08ab2ac930ab49b40ecb44ad3d4bd8dcbe6cdfc9c104bf" },
                { "af", "25a4a7c13c9d96a68ea571c47c610c951449422dfc47f14e99dfac76aa4f3da4e791e5f9acb522993460f152ebb82fce99216d085007af69fccaddf568901e48" },
                { "an", "622d48be656864ed27d225e66f6741f1a8132a6179824e5134490a23e0c7b6ffa859a3829fac6b548b2f4bd0312aa1dd1ab739753026be25b0839bb887de407c" },
                { "ar", "21eeb349e2584bba42a578f23d625d346f155d9e49f5e193ca5d29d47ce8579ca89f4068483f19a81cebb25aefb8fb165c94086e8749d01e134dfbfc26c51880" },
                { "ast", "64ca877665933fa5171daff3dafa9003685dca2bcda448f637c9b10d2c413da8181b43c0e21aef75c0eb9506a16b8654aedc2dd6e9e48bdd065f9101e36c586f" },
                { "az", "3c91d9c7be5ef62dc8d391ae753e413dbd62d99fbeb9d291fcdaa7d6d1e1a523192f4ea06cdd8c859d5fa0f2c49c96186af146db5a23ef241f5ded7f905f0c53" },
                { "be", "2e4317b0336e348c594e87cbc2c52dbfdbd1fd997f4f04cd3966558db2ecad73f94b83035ef7372d02fe7c03e17974e1e8f468c91a663c8df8bc9a52bde97fb9" },
                { "bg", "c8cd4a5f53f0926ba58e63520f9dbf1d9f0ce8bcb6d706a2bfa06c622b479afddfd94fb1b96191660c0feecedd530cafff2fda034c8ae3a9ad14b8a5cf86b7a3" },
                { "bn", "2eef7c5e1fadc701fb09e495bf850eef82f6cce3273cca7977a8aabb69b8eaebd594b5424b37520cbc20cf7a228a4b93c6b4d7e3dafafe5017501adcb864654d" },
                { "br", "a23e9e4936840e22c6e9514d4cc0654074d26fed7a7fc61a96b8e55f69b56430147aabf168f2d17d7093051c65eb19c87c58f69eea4ea3a2902a319818c8c187" },
                { "bs", "aad5f66a0fd25415ebb2732ed4d323768d0bc2769d95a921bfb4ade8da0acf767ae231400855d8d35dc107243163465982417d5b93a95a11f68e1ec4aca8c4c5" },
                { "ca", "2ae83b62b1b738a5f9f4331769afa424d339dc65394c4eed0390e22ec6682f91047902fecca91228723d240e74f3f66b5a2c1f6a0eeaa8126c632fd5d14d1ca9" },
                { "cak", "533f522b4717e3049dfb88512d1c025963ee546fb39ed97b8341ce541cda9b5a000c3c2c18896a407c69d2050e6f1d43faca7dc1ceb825a616f445d0c29654d1" },
                { "cs", "bdba324d94bef926d163594cc1b8c274e32a7344a41a1257fa257a7ff41e97edd8fff34c289700eee8894193b03241362036a32316dac841208b6f1e72b7223e" },
                { "cy", "bacf47e5d7aa690e7b1bbc5fe932cca8a2be0dbcda9188e3909c1b1d2ada3925216525d990222c20e00fa38458c35e70ce08a7217252518b4ac555c49fdf8ac2" },
                { "da", "0c48c49b98307d7a74a7b6ccc356cee817e94d90d1589fc1669154bd1f2fcf8637fa2d5f2dc00fb7769f5d4e20d77cd3f72e72679058767a53fae813e8271603" },
                { "de", "c6fc4f22f304f2fb4bd015d732bb765036323a856df11b928c6cbbb7c8eb90386c77792a727628156e082b2127f699211a1ba21fe7a1ca9a58e60d49377e3ace" },
                { "dsb", "3261d645fc45d399ca46d43e4fb09c2bf881d618f6c3543c83bdc8c812ddd488958085d989025c25149f31047cb696f29c06d5fcf59d960903d338bbc02eadb6" },
                { "el", "55e8fce9fd2203e6c50fc0d80586a703153266bfd1574d8112f776282c7b0adaa1d8c701238e55740e5dad39df65c3245c09c8c1c9812d164d3380bdfe5df4cd" },
                { "en-CA", "7e3868d94850417210ef4f7aeffde05601c081a939b6800f7c3314e987bd3c5b5d3ddeaaef65fe73edc0f2bbce26275590381a9dde2c7812af31e7947256bde6" },
                { "en-GB", "7f20004fcca48635814474d4416c788715fe4ea50b37bf285e580238114de94dd2379e4a54aeaf26c4dc18cc39cdeab52749486b4041c5d116821835b18de7e3" },
                { "en-US", "ff57416d3d76efbd10561718c3d4744b4c22d19668e0e5f15d0bcb341dea03bf879f69a1625d178799e375fd8c3de10dc91419330ea11777e0440ab544641a94" },
                { "eo", "728d1abaa409cc028ce6482aa566c54b8cf258eedc8fb60b107a7c221493effa16ddcc0cbb6f5f6ae86b70fe35c88814c4443f3edecdc19deb84844482032bd7" },
                { "es-AR", "82e5b9df258707fda6045c899264821998fd01b35509184629ec8c7327210240e0c67db664ef10f7af0408979b0bba9322815078a421529e5b1181128339894b" },
                { "es-CL", "c3359c9f6967d605b83e211d0df722ecdac3642b245397f47f0df717ea705546248343f7725254b9cc4d171cc891951b5a1a8687fe164881d8f7c21430945a6a" },
                { "es-ES", "0e4a2921a44b80392c7d9d942a859ec38d279f69b639fdc8bd6769bbffe64b4127c00da2ea4a0166735f4fc06c210e120f5637cc77dd0f82ed6d8db047dc2921" },
                { "es-MX", "a3fda944ee51d46e386c9cff239900fb6911abc33ebdc944f60d7d687dcfd408d93e97b4c52d60b83aade77c5cbb4f4052be53af778f10080f297242c0002d47" },
                { "et", "86e731cd733eb3592f1e12c640b95b8c23acf3b8453ae6108c0845e6e9cf5b5699e1d8dc4d98941dd8fa5c7b4cfbde7b8513edd8083fee561cdc83886d2592b4" },
                { "eu", "3e678dc6fa911eb83e6e83a330db8dbce35a3c1817ce2d1847cd9535fbd5a42ca65ef1ce882ae7c185c9685a5fe6db8f1472151d7e8c45bd9fc3d2e2c3311af0" },
                { "fa", "0632b25a3c1306faad27db15749ba08c792b624109d42df9aee8cd83e26f3c3a50be3916468bbe607ecc776ab71f6e161d42198ec082b8f7e9b4fceffcaa6c71" },
                { "ff", "a7606586e57f637330c79d7fbdb9a1a6c5498af97d308414bff162ba7128dc8f9ce2a424c3a40b4acc52e3d0d2b47bb95197082085a3e088c330289ab7ec60a3" },
                { "fi", "45653f7b374f30e4b9c401e4b8facaf0dda6dba9a5042159fab8b3d3345cce52acd2f5b8dd5d63ef8e9bb3b6943d6996014eb39442ca6cf068cdead8e86917a5" },
                { "fr", "cfcbb853aa8438c1392c2d49208204e1fde2c34e97ebd9df3400e1fb8fb60d37ec56b39d39c4381077a0a532f60f04acee9a25f440e155a2befecd531666f942" },
                { "fur", "2ecd000dad51fb1aabcc37ccf4fbf020876f0e4b185fdb302374b55adb90236f6c70f74bfba4f4f3d03be0f0deef334bcb48ef910ce662f25c046c7516bb3cfb" },
                { "fy-NL", "4cde8e12b5ffa228e664bec23a87ea11e466e1f13f6e413712e52d6dac79ac890be030a04bf589f81cdb2bf29829a438c6a25928416cba8e045b986561fd405a" },
                { "ga-IE", "a1bd726d5fe88aead7ffe5aacc3a9b3ed86b15d56fb69dd87f7f63584f5a62c1c278373743f253ff0dc69b5116ff005978de8f709bf190db17656f7bb67ed7b5" },
                { "gd", "c48b9ecbdcb23206434d83f0a2a1590a7339e3822d600e823af8941af32a09d2cd3ca7480e19b59a293c6f84a3aa44f3d7fae2187d9272714746251e6ae2948c" },
                { "gl", "f8145106adf3447d402bb10cd5c2bf55e10eb67123dab6687675243e3b41785dabdd2d85da5e06bede9b26f21074f7b6550c5b30a7d513aca3788e2a3d1dee7e" },
                { "gn", "a35786c4b978c653d1e8c9bd3e239d44a06602ead28f930192540e49752902809c3eabf7db7b115a018e3203719c58704e31b057ee50e40c63d552cb2f7c89d7" },
                { "gu-IN", "caf2b5b1e4e64efcfae1d8a33db8a0d95bf6dec0297df32942b6949d1917d3d20739d8eafdaa44a98e28d44124a366c655e72917dc777ba364f442881026aaa8" },
                { "he", "246d60021d58d5f4170cb5695bdde434688f61c60fa24d8cf7ea7ced830120103d59feb366ffca6afd53983ecf794171ec9810071cbc5b800d0004dc93c369bb" },
                { "hi-IN", "ab67901237fc71e3e75b9081cad629daf91a759155614dd316af3234a4cda9aecc3275f9f0627b40226a498760ed7dd2328159c04740961b35d8e7ce701b92a8" },
                { "hr", "343849591c6157bfd7d243c22db7780ce8dfe510b3f5740ee8e1e137bafdbe7d20d9c1a9c3c8bebd04d2bf2f4923a99f6ee1b92d9c97e667d86d21fa1b1c0c44" },
                { "hsb", "d7d2a0b82f7b7da665e5244592939c5abbbbfc343615849e8fae6b1b28162b26fac39324aa53e122fd1764ea446c6021cb5b94fe02b34292cb7826bedddb30ae" },
                { "hu", "e79df10e8ee4b3d3e8de2508422ed9346efb801a314bde5a32570b74dd6985876b1da5370688e5675fe804aa358c8a089bf25406bad5784e8a68751a66ab5a7d" },
                { "hy-AM", "4c3d8183678883963a9d74b3fb9a1c8bc4ba2f6ad2e121ffdeb9d38c02c9edb1e7073247d9f7c492ed8032da6ac7232e1513c1444cdc4ed1b7803d6375562fce" },
                { "ia", "1d31e689d2300db0148b1d48d02a017eb3e31309f55e31e62067c71b270d1410d9f4b53ddd92a30cc33074cf3393c5291f206f0ea406d73fde76759f7347711d" },
                { "id", "5c5282c0144f4f287cfc107ccd16a0d683626a7bbc7a2c0eda09b778ee51faa39dc0e681e3a949d15d362c04816cb890d07b2fe247f54d3d8280f9d864381dad" },
                { "is", "ad68c5511f0cde7d071b1830b67203daa7374a036104ad1f8a508e317de754081b05d5f891f2dc1c92a3850b8a663533b9d5a7a83aeccba9f987d1b352ba76ba" },
                { "it", "c10ffade04df8cae8e26a00c38a1ce99f141619c31619d4244a266b5245759b207f55e301b124f76f1ec9812c5b4ea4100e2512ea59cc3353898bbf7683772b0" },
                { "ja", "dac903e068dd182837ef6689fd417d8206371840e2726fec67b0988caa7a80ccde7676451bd9d218214f425d01b0c57a9bb6956345acbad4e5f24e99a917bcbf" },
                { "ka", "226c75d07c47a2edd77b11f853728360d7d5369c325223e16a5dc425b3a8b1925fd0623088204177932d45c037aa1b4fd7946f097f70ad884816dc73cea69510" },
                { "kab", "e9aa9642f5d3bc763f31f3292ec299e221c112b1dbb114887e2463cbbd9e3caca9f0307558d828add123bba2347351944b64c6e7a4be93e365ff09437472b3d5" },
                { "kk", "e4d8853cc039c9391fb87aff3ceea2735c4b5fc00f545068c151b47dde65bc18c8fc8ae6cf8a4be556fbe45024f25f81c68a688368e3769dcef3c67f69f3063f" },
                { "km", "879bc6b0db53e10161d84269399ff47d0cf6e4bc56619785f4f324c4ff75f7d190c15c968c297e1b6ea3522bd22f3388c5deb24a40b997d9df5707ddeb6184aa" },
                { "kn", "5b45474e86ab08dc7d9b2589dc24ec90480594cec4f7286c8deb465ef20ed901024fad641718e237259b8a3c7d4a44faf41d047dd1f4b4d85c31e329d738c7a4" },
                { "ko", "d8e6e88a85f5e669e3895fea238dff7ed08b5eb50a91fd255d1ea71eb3cd24070f928595720111b569a4ecd70789a2f68b42fdf20b53e2f791099e251c586cc7" },
                { "lij", "dbe5cd55438ac23208879036f64049a381f9fa6d157aa053e67700511248a7b5e1b0bb1c3bb9a2953d7fcaf51318adbb97ab3b138a3233cd061aa4655ce44b8d" },
                { "lt", "e222a5a82a42f7a6fd5bf9643bebfb6c378af854ad62467b0a2ff72c3d77d06809512c125eb2d60a4122588b98a002859d626e54a2d799e493034ffeb13da33d" },
                { "lv", "9511ba91fac3c2ec9a11bb50e8837a5cfb66fd90c18047c8f74c8f41fbc7399c8f7621e40843c222bc60baa773264166e9ec5ef77f801d9e1a6d735bae31c079" },
                { "mk", "ba8ba0175ae50f0eca76fb95f6de8631a82d6c2c49ed4b6367a890edc1d398d3ed9f0186b71e824178760fcc3c3f7677c4a5b8972e83d2b7753636fcafba24cc" },
                { "mr", "ce92d6f55b65df075f1fdb916e8fe82983c2542f1c772a6e0b5c72d1fc23fd36f00ea46468413ec90532f0c2aa754a86220b291b6e4ef6cee87db319ea584f7a" },
                { "ms", "480b7db46743c0c00fcd936a2d74380c6c8a62009eedfceab05d28ed0000e1f52b035c36d9420b41b8abe4b1d12e74c2ae34a2444750c429a3caafd563e685ed" },
                { "my", "ceb01b5ac688e870141bd274ab94721ef10beab5e600cc4543b6b8d70758c779339b98e86431da903fe98d7fa645dbb67221a8ffb7457ba4dd78ba6dde2ac770" },
                { "nb-NO", "0754cdf590872eebb7c41ec081e324696a5d144f11b6b1e9b2fbdecbe84afa38ad96174ac59d8adc0d89543499031dca82cb31692a9911768d736fb7f17d06ac" },
                { "ne-NP", "d007114b582b03f5d87c0382b5aa67a7d3fe5a29694625b264ac67b7ad1ac3e2f30a9be940e725f268563078592a57035a504c7859741db4eb1736395be1d660" },
                { "nl", "2d21845750c134b1dfea1114c2212e6dc62164bca29f847fc9a618b29b378922ad86ac003a947bb81e22ef89e2c2c8898bc67e20622e9d9878e4366d19778778" },
                { "nn-NO", "0d570f3dda6b0ade30af18855aaa846c348a9d47e5ae83d0163587f794bbb162dd3cb9fb51e3169bfea955cabcf3e1dab82690ac711c65ee0a9fde2a2dad365b" },
                { "oc", "59d20bad3771b518cdde86db1b7cd2c89bb9f59fc847f3cc8c2e12f7c45d31e3d0d298f3d6366db63c92a6b0c3c2e642fb06d3eba119b6ddd76dbdfe1431c67d" },
                { "pa-IN", "6f6ea67201cc32682226eaaf4a2e406eb63d17c6ef9bde10a6bd4896874d7382c08a72a11653a6b8e322a331a8b84ce53f95606a41c1a1632718bde09b5d4630" },
                { "pl", "48818578c86211a22af0773f04132770f12dfa2e97eb0f8cddf5ef8a30c974ad4e9d1ebac61bcc0c22f4c70011043109102af2aad38fa0a9fe01f93a06e03609" },
                { "pt-BR", "cd16b4e6507434bbf25ddaf0c225508a4fcdabeb9dbd76a9777ff519cb9a626946ef3f1623475363ccf2ba08e450b505268c7c25e6ab06382814e83d9c3c52c9" },
                { "pt-PT", "dc42a82df1b7d89affb4fe78095f812bcdcdfe4615b01efcd81ef04e73a3920d45d684d96a32d7aa54ade9797843cc3f2701bb679e4cae80d5f30c6f2a47bae3" },
                { "rm", "0db7227ccfec8f9d016fc090ea1b461ee449de86ab5085bebb8e8156bb2c326f05f4a24b952b581107e1f430d883e2c8e6ebeb7d38e5c324f34abcfc70afd816" },
                { "ro", "2d450ef285ea453475bb9517f87ac83aee4f42a26bafd618c149d80de2a0c8839c36fa4756755f479e7798d203ec54c81f9c2a98f522656124b157b17e98e048" },
                { "ru", "2d325223c11cd4e3a9e2caab06e4d76ed8b5ef8d73eedfeaf930bcacff2844a0c6aa8b0b52cccfc2ae4731ecc26bcb371bbf9858834cbf25ffe0e10b04aacc2f" },
                { "sat", "4de8b65613f7976701d4aa0e681b0148ceef3de79a4c2555b52e756fcb4cd16eba39af2772f306e12e456636b802c11c35d00e034b8745fc59b650693a10f7d0" },
                { "sc", "f10b5995825e0d4f330a08338a1cd61a5430a9e5c025301b87c7dfa03d191a312eb0b5613f1fb6db45a1f069d26a803c84285fc5f525b24a862c14ca73e5c5cb" },
                { "sco", "9477bc64c81bb3d6a821b8198b542331c80e33e5af8350b426cc9939f6fefbf7bba5f1b539f5b7a46de1c9929f9874ddbfefb70508f4e3eb0838c012ac9b7b70" },
                { "si", "147281cbae2939ddad3fee2df214261c31437a5423d8c4784e7fbb807a8029afd54ebd5ec060853d548d173687fcc6b87034bc81315fd427bf4845390635d9fc" },
                { "sk", "6652c48d6b9c17f141a3ff26abd25fb67f6626141b73b7d2f551735464d317415c11d6993f94f590ba6911489d17dbf7ecf69a92c85a93368b673d97aeaf767e" },
                { "skr", "818981f2bc81177d77d3ae8d6abe836ade837889467f17ba9ca9eaff1cff78d67a7079058e68416b8a40ab591a2c96b56ba7c9f8bff8cd42a5b57d7510827111" },
                { "sl", "ae14f7dfb3551e682c703c1abc45328940ec8ee35932c41f5993974c5e88323c0fb673f096a3432559ba9cbdcd82ba69a38712086593395040655dedcfb26d33" },
                { "son", "62a75a34c7588cea7c1eda0cac9b712dc34126be552ee289b02043ba32f5a03813cf59925ae9073e0b7a0dedd88134e544cb4ca61112bf350aba8cda91e5825c" },
                { "sq", "910743e9139481a108b79fe1c32aac8e92109a255cfb95a7f9179d83933952bfbeb7e910dfa7dc11077889ac49fb9ed43aec2fd5c09894fb5be17f0e808cc48a" },
                { "sr", "d087505fad242ddb62b3daba68059612ea3a09b7fc5c3223e9a59ca6212056045e5ef4f3e1e675aa2bc1241fefe9d3d266d696aff0d722d697f069f401dc6cee" },
                { "sv-SE", "73470d070b7f84921b79d2bb4c499fd001ab8cf22928f17eda322dc10b3723ddd69df88e54e508d7dc8b524b6bb8b2f7da9aa86ae62d5b3eccd955a962b909b8" },
                { "szl", "70abf64879df7d193c3890d519c5f8b29e6b9ef7a751bf47fef31690a44e6fac19d40af40fd9709b66ef86b5974603d4dc796a296eaf07277c81a021b91ae99b" },
                { "ta", "0eb1e1ef5b68a7afa882fc5471d86cea72031b09686e1c9d56247d259f6b90d628214d93613a703003788a40b407868d0f3d7dbc49dfe5b8a08ceb9cfef76374" },
                { "te", "24c99d2aa40dc63f1c8f02ede67b148a5f66378b8854bb7db5218d128fc46abb7de9010fb27465aeec398b46446b2738ad2fab98cfb7e2422170f848716098b5" },
                { "tg", "02513c3b08067599c0b7f7afbac5d8eebe0515a0bf2babb18c13ed2a0e0828cfb3f54e03f88edf42eccdf554ceaeee4284156228fa99504e0816752948acb4d6" },
                { "th", "0dba7260e158eccb3180370568789cc68295cb293b83ff9c88fb8a777e7e31537c294a843a8403ca04a48b996a082d33503793b0a41a1010f3dab514d3b312d3" },
                { "tl", "ecdb71d4e5d436070ccc8e884aed4ef760f783943d2fa0d153e1d4c5f4d8d3de51a3a047c7a36ce992d3af34c33ad620257407e18c28aed3edd1aaaf0ebdd0d7" },
                { "tr", "522b40485707824f642290f17e240ee92d77810b75875c24356dffc9a8f93ea20f254e0c3d1ef17524a62638cb7ed256e849be42ec2eda563ccada6618e0d433" },
                { "trs", "877170a61ab53f94b1e5d781a11de59ac0a3aec8702e6572cfa42b12da958b8c9db292318650b4d08dc361304965dec6758506dd38a74d9a142ca05784de3980" },
                { "uk", "c4dbad78e5a2d6ef8ab8924f8c56b613ca2c805679d62e2fbdcb5ebb60bf03884e487867cb317731ae6663f02c221b0fb475b767a1795d1a3d9b4129a98952b0" },
                { "ur", "6d3f1f8e2740870a6240fdabc36a4036e9e753476be1297c6658f1de0514207040a5a3c86f93661815fce1bcef5b570935afe5ddcf51597c2582448cbb0d47b1" },
                { "uz", "d78437c711cd4a6b62857d5aa1d328434184288b5f65993f3189bb3e899c933d4aeccd2411aa0e88e4ed36423cbb379b85e6f8f188fef0e7af340ab5db4858d8" },
                { "vi", "e6839790186c0861c5ca7000a59cccc238139cd9874fa9aa61dae8258b9ebba249196af9c7e6300ae90677d8546f77dbd73d0ced1c75a94992201fe1b768e499" },
                { "xh", "e4965c2e704829e5eb3138a7f7908f43a14f6bec261e1563e21d55a13e6d7cdef7dd2bb5d4cc15edba62d5dcf5a2af17031bc052abe61a540d64dd2b370220c5" },
                { "zh-CN", "eca08b2250cf44289ff2f22b65922ea80ac283165836389d17dca8d59d50ed1868a36595651d4b376ff2c3194d159d22aaea53ec645d5dc8c5f0cb47550c2d05" },
                { "zh-TW", "85cbcb3fcce0f6e31a50166fcf482752c4257d8fbd9169a4cb9f27b692105d91f4c973293c7e8065b4d406836e7e14ac5bc26d2b7e28425a6d18d302009ce9d3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/128.13.0esr/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "c8ca2ba9d90244b27fc66605fb4d8278fa25bfb9c7d014db13c131d64bf2e205a05e6abd52ec1732e776ce013b23fddf31063a39b43cd934b00efdec7ff38381" },
                { "af", "69ac322e882c45cfe1d22c8901f39ee10825c63bd0e268017420bcb989e1482b1c3956a69208ffb583f010c13a707da421a75bc339d9ba14dea9a41624adf254" },
                { "an", "ec28efc2ab276ebbf44caf4208bfb35d79b2ed94c3f8c4551dd658ac6cdb4021f0cc7bca0e3876003c01e6ac427fb368e97dadbde14bbcc2c245ab8dd257eccd" },
                { "ar", "db385986e932c439ccfdeca6dc367862769aedbf3a5e974454308125e3fa805d4deafbc31b5f9130418fd73b3701bd8ddf83fa10a7727284cc7e33691628128e" },
                { "ast", "4566ca55b6144ff6df273d8bd22cfaba54be9fb5a89264da84bea6da566b739e8643b37fbcb165a94977fd33017de1ad5e72288b902ea2b59c33864aacc0b735" },
                { "az", "f9ee5fccc63fdb549b08f120a49ce4aba7493ddcf91a6b4f974694ee4245335532e3cba93952cb4359c939d099bfc3b72891e08c611ee6b0998db34eedccee64" },
                { "be", "66a010548bfdffa65bc8f0788e25a15cace5d09dd0b00224b6c7ce514cb389dc123f227639aca270943c989983dbce510f01eeb5e688556e649a16df4a31b399" },
                { "bg", "04641c62fd50f018f7dda37f33426e668e6acad1d623d1713a403381bafe0ecec394d87bfe656ed9039aa49132707f7ff7156a909442e4a68b947a1a1ab55a00" },
                { "bn", "c98f1696f04ba46a4d576ff4be7a16fea1a4ceb204cc136dacee9a4646f05ef68703d92a2a10128e4400c404d4f5120b10361e902667221eedcaeb37b6b5ef2d" },
                { "br", "56423a73993dcf2680a94a20f522e65ab73014402c02d32098d446d0d6d2b5cf8303f4786d95cd929047c2e2ffef4fb24f5d116f8dbca113e2cb97210c951b4e" },
                { "bs", "032cb67f1d0f218e6daa331f881b02989eea2c9ab82749d7362a56c4fc18982eee066cdd0f0fdc02fa37cd89a252950a0615a64ff37b45c198a87fcf7774aabc" },
                { "ca", "bbb6d78e0abda9e253c1b528d43a2f88140fdbc217f4daac4ad07f0a8160bd3c70d4dd418406ee68f84514852d119f10e1e62fbba43d2413a56bb33935fe7bc0" },
                { "cak", "163b0f11e7e2a42ff21ccf1a551d9e7de5ac99a7c937bd6563e42a40708985027aae597e245a9b461f7b0aadc51a56b09485bab3e806b14f7590286c1da0987c" },
                { "cs", "5ab5353d0abf7a5d0c5907aa4693c498483dd7e30bdc6348a6225835361ad9af4924ebcfb8e32e60ff08c364caed0f6751fa65ebd61003db0e55dcc65a76e2b1" },
                { "cy", "e2881378dc6e4cea3f8a7fa2fd7cd883fda6153a1120c77680571136f3313bf7beba0ae2a9c9be39e55378d680ab7ed0c330a9cf5e99b22f1dba03ba1c68a9dd" },
                { "da", "35ad36bc7312ebfd1516722a3d373877c24ef6e437f52d039f62257752b72f72a510c5db64100b8ecc39c6e0321fcc2cc044e55734f3e3abac1601ba442e5141" },
                { "de", "d0e326a0b99045806b8039862ecece97289588781915e853204ef5f6ff7313473f34ef6c6443d677b501c9293f3354b0a7b3754c8a1b291b01a95e6d0396dd14" },
                { "dsb", "5a40a24ed8cb20d84345d929769e57201e62933ba0900d58d681a407e9281290162ab84db9affe4c4db9761f6731c8c1d7be40a1479bb246473653180a3deab1" },
                { "el", "7ff6b89d78216d00e59108c02420383ba4b94b372d7e8ace2cb71f3d1384e845812bb57d38f42fb38543b4c2f31196a3102500b24e6297dffa54deed593a2db8" },
                { "en-CA", "d4ad047df666f43a0f85c9e2f485ac13de534ce4b7b5280381f7fb8c1e1922926d77a0bda4cea3cf47443d36b3a1dbff978b956acec339178e427272485d7a21" },
                { "en-GB", "dc73f4cfc6123622444ebc36540d0dfad8a257c410041ac6670a3732994a5c84bc58f240d586efea1e95cb22dc4026e062081a858f942d6d9fc4b2a3d44cc1eb" },
                { "en-US", "e56a4560f438f62ea0cf7492c3c5ed3029382fdbfb7979704f7d753e3db762d982e7ec582756be184e4984489951ed7cc8a40d3a0f685bc8ff4d1299b69bd638" },
                { "eo", "c2448e93ae207ced99f2367f8172d2d38eff8c40ab3ad133ae430a848da9e04774672afbfb49092143b793bc4a5d9b967e8d0823d5bfe9d1cbfa5a048fb24a4c" },
                { "es-AR", "ce0fae510eb826460f7ba869c385adc245e8a634b882c2a047db67a935c912e41444f99185919221666b071a22820e2e1fa1c09a0d2180da200c52823c57b649" },
                { "es-CL", "fcec0b621569e152cb402429d4b424dde44307150725359328bc497ecb9cd8319d55aad53bb186ac7baac72ba5e845748747bf35e2f6ce7d2435081cf52c7324" },
                { "es-ES", "301f597706f582199b75f870ee5da4e0d2f26f4bf38b995102cbe0b848696049d650b8030c97b3b4c01853d97e97f11b7befce4e4f9b3de2184af3206c425e15" },
                { "es-MX", "a5201ff30acb55cb3a139235db45a608a8e6e9d9ecd7c3c6f180f495cca558465bc67c84c17fb29ab4df7020c804ed341fb16a16f0e563b4ad26a4f2bc181aca" },
                { "et", "97e07db5ad1b493cc84250934ef9d91688c5104e137e06d5f89c7d6fa250568bd4111e3bffa02f051ead7f2fc9b7f97b1abe7a8066511a541b83cdec0258337d" },
                { "eu", "109e88f8322cbbc7c2298eee82fa9afae0c53c41b2c53b350856eb8c7f8969ef22d413d430298e36219a420687737861be154157179817b0238f490e2b3de773" },
                { "fa", "af1dc14dee56d0b1a589c6f5c39910c11d115efce449cf9aa8fc2e3f1c0b4b194f7b8a2eef7192ab3774bb5ae06a571470325627f547e6a7d9537d5d72d0474a" },
                { "ff", "a41b3795e9fca39fb31188c168bc6409f332e1f5ce16b7b0bd30f5689c8ede2ed1586349a8f70bedd9ba90b3a20c2e9efaeb58526539ee5db554a8496515cbed" },
                { "fi", "cf43952983d33e6c994d6b7c0916eba570836d0720b702a831e3b154a0d57dcf7304aac6b7476c732ac5074063d2dd8a0bb3747d0b8e0ce67022a8b8a1b9cc87" },
                { "fr", "e05ba58b2642dd40f38f33d724dcfaacae3d8bc1ff44a018b8d34c1a0038d75009b23e314a86fbe3c052ead3e78566bf9b9c9756e239d6987e5c8559aa3a84d0" },
                { "fur", "590e39e4c486e6efa1a90ec4fedeee877b395095eedb458dde503443131252f418fb340810470a06a0c5f3af3c79682e040190e84eae64655f71a27810867a8d" },
                { "fy-NL", "653fdf7e09f0ba5ded4558d113071a74bc55652d4e42fe0c51629d054cc3d71bbc226f525bdeeca661e5be2ab43bf41e5df157accfd8e33f47ada5c8ee294465" },
                { "ga-IE", "87db45e0211f411fc0943424057ec6d7fdf0b8c1399f1e92a4bcbd8d651018aeff91858d17f8ad20c503c37b8c1c03ad9eb1a01fb6c461aed11f43607a68bc3e" },
                { "gd", "a596dd02a0449e4059d5408a8331f0c8a2300b19ed0836219b1027ced9c2432aaa9007fed695240c0e55aa25272bd6e9dcfe25d3650df24bf7f1000c9822ed8b" },
                { "gl", "98b8bda752751cf53c977729baeb6c8d91029a729b77ea96afa828ff866efe52aea54a28e2d9709d4ed52f8bfb3c7b4c80f9f10483b2c3c174833e3ec02f16e3" },
                { "gn", "3c67c13e14e23311c82b60520005bebf2c5fa689ac4811c21d188435a8e5cd409f79b55ef049ba9e5b87bf8779b3a9a05b4e37cffbbfbf560d39ccea694665b7" },
                { "gu-IN", "227d474b36be902be752b3dca200c69f8457d6e94b5a5e01528a7adad2d77f55bbc609a5de8ad3c3ea1e0846892f70798f3e6bef538aada882a9dffa79cf4feb" },
                { "he", "09df2660252218edee30c6045eb6d9be031f5cdac7de52bb747faeeeae5eff7c0fa8ac50d36460bcbbadb23aff5d6605ab061bafd2fcb7d5ac18dfed152d496a" },
                { "hi-IN", "60370271636d35c1568330cd273d770fc7216057d40a07bffc84a4b336da6fee9591ac1895813c432b2f3e475bb0296d90bfff79f4d51fd7829831dee15efbab" },
                { "hr", "2dcfd56b76aca8082d9b95d349766b2823001193baba15c1759ca2a8413951899002b5f6159f603736b4b9888d1a9fad572591f3e7e3ac4bd57e7c835cb80fd3" },
                { "hsb", "7d8ce13f8ee8632b59f36c9d4f2def43396d186e8c66d75149d136a2af49ca2def2094ee1ba3bf5222acdae66c2dc61c922df221b39c19476875e0206a17ed69" },
                { "hu", "35f5ff2158f755bf1ca3eb0a01836f493dcc07f55e70706fa72de19f00d5580a4c0832bd62015447a0605c7f8603a308317d3c522e7c76957290bc40d9b93578" },
                { "hy-AM", "4cac80b6f97ffbc6322e1cf9672eab42ab322a48ee6ff79910560bb2be7461b7b07bdf0dfd5ce8af50f82b5421cf052df885250049f3ce985a243939bee37d38" },
                { "ia", "6a50291dc13b4bf3fbf416add28a9cd8fec984ec4c97f0e902e56c79325c85637134e25aaa93fe1ccefcbcec036363737bc182838c5e9ffb5d1619b5868945a1" },
                { "id", "b3be362ba681bd6e3a38757156683b5964bac5536c8b901aa537de920d183c06a272afbd108165102aa995854320664554e1daf9134040cfa28abdcc5baf65f1" },
                { "is", "94895135e2115f43b9b5b336b95fcc3a8cb80e29a998596e445349dda9081b515f7e98dd4ea3a2e09baa64819adb1249c0aabaa6d1a005e9606fb983766df5e9" },
                { "it", "b0b42fb9ebf949d82138fffce5fa5ca8fd9f96bcdc82347043a6ead3577a3a79e411c362283cff2b40fb4f33d4756e6edc741026428f656e63a399e843450621" },
                { "ja", "561734b6ba5ea2862b35e175bfd8665bac257fe6adeedcf35238dc644cb3cf07df3098c0cd4b85de89e11e9cd86b9f4a8993bbee904ed9001e3df5db585013ca" },
                { "ka", "ebe3f2542332db438767c80fb1a15e9b0011014e4399a209f9b403dec9fb496d5db11bb6bf3555d0a5777141dbcdbad0bce130e9bdc1895e579f8bab23130115" },
                { "kab", "38caef5706b9679c5b2a50dbc43b9ac5504812f2dc44111409a860331527e06d9ec4ca0a21b6588ff11558401cb1431d7e89647b7d901ca59814a098456411d4" },
                { "kk", "b96a69f8ee383e4b16348bcbc2721aa2c166e907bdf4689b0f2c922095aa6a1ce9a97d06037490c8d070d294c6958c9f54ac4bae0b99f2ec6b23bd095fccde94" },
                { "km", "09e1caf20e84a47a65010bc31dd54468e9a942ccae159115d2da68faf83fb405a7a72cc5bd3c82e86dfb3c3159a3603e8baea76aef136e1c207822b119004905" },
                { "kn", "6e98c8c49799375638c1bc92616c28e2280f25420243056d155911f1dbccaf13eda6c5d13ef7a05cf49ae6e3552ec38bad9abc62689ddeb779140e219fa425df" },
                { "ko", "addcbf4b0b645d861e4d373526a6aa5dc6ff83d862aba91f2b1ee9a81a55bfda6e852c65a7e6b4a83b9dadd02c5b921f5075c75840708d70f0b62e300d8bcb0e" },
                { "lij", "a1c7209504cd2a4c4e20551d476b6abbe6ac758340353a9f0c35dd6447eb736809f7a58680f2307b91ef48dbb3cb21ecf9660d58e572f6fa519e4804b023cdea" },
                { "lt", "579413c2c30521ce6e639d5d5c3a5561150d4770f7783726ec4db4ecedd64cc1d748fb60485d237f2a2ea65088bff4e0bebdf3da04b0c5d87807585b83f82783" },
                { "lv", "842c249a1dd7ca6c3e12ab66e475044a3f1b746c208368bc7f5f261e0125786a38902459fc9061af74bd53e427051c7ed1a8229a11d7e5ef3e465890e143cb2e" },
                { "mk", "2200ad5553dce176264bdb9ab3986a2f81f613f9206e19654b6769bd0977f6a92756f3b9dca160c544e40d68444e226a87309e23c1426106626f155cc450d549" },
                { "mr", "bacc23c863173e3d7dfbb3d8b5131f1a17faff3e6f6d09d016a05504e17b30563712838d1cbf61d4d08b5abe3d2cc11d4a0e9af6758fefa348e7775342812740" },
                { "ms", "74d5cb235ca919b1b15e7ff7c120d90de940d0ef67e44daf6b8448005f5adaad215bed49853c66f1a5e813a0064b0c1ed07f70cb8caaf67bc7e9da1ef1891acf" },
                { "my", "e81cf920f2d9045d51efb94ecef84ab8a6c70d0a476ad1bc4e17ed2613be49b2f539ea955d2e1646206e2c9b1272afdeee1188e212891fd29b0847c8da91891c" },
                { "nb-NO", "3fc710952644d50e77d00d23db5cf5dda5977e631fb88c8e72e2286d90362c33cd6a6ef5b7a52d21a17ab87bcf153b0cc9580a088483c8fc012e27b074dbead8" },
                { "ne-NP", "bbae576295f0511c2f47409b14b3ec5a355772420f01baa16b32bdae0f2aeb0a69df9abe3a31d2ba7b9bccbe89245dc90d9e8bf35df1776d9821b510fd5710ac" },
                { "nl", "cf1ccbe6357ffa3bd3eacaa359c37aa808a0fb9db48ad5b0b2091000d328e9921608b7252d16afc6016fd8c4c99d932cae4d23c3db61db14eee2edf498253c9b" },
                { "nn-NO", "f754f17f0833f1eb983fa57a10be16afb20d2a3e211463bdc95d8ce5f78291881e7075232d4abc7a04c8007d1852524bb8c3817906f0f10261a3630eeb1917c7" },
                { "oc", "73dcad52918710191ffed73bd241b6cb29da0033e809002954e24de224ee6a992f59b7ede1ddb0bc5eeb3e18801b7f9ec739f78424ec77ac6bca3f95ec1b9e0b" },
                { "pa-IN", "c2efe40fbaafedf607fd6ed2235bdce94e1ab9732cf9f3243dd0332e6197d97568e4c07a6d834b913cd372a0316f9557cd17c04677b1f94e7f87e6bdb29f43d5" },
                { "pl", "0a8942f4a4974935874d6a5f12440a4b2552d9bc2bfc82f6e46b12f986e4aa9586e88a286aa821908d723c6c79dcacee5ba46ce73f10761a6348997d0d7d17d6" },
                { "pt-BR", "ccbd3c6734f205c380f88696f54a8635d881b73666a5dcbe4a8eb860d15ba67b544079e682562baf13c1b5317b2ef9e6f8d9a8d63c88aa3acb45b1e4319a04a0" },
                { "pt-PT", "dada163e3889d867c68bdec00da42a3222c38b099a0d320064e7c0cd9e9e330ef0b62b194818aef66df616deea38e82f7d0ee6ddf3b40c407b6b6dfbb7145c2b" },
                { "rm", "0b32b9536542e2981f8ee55ebf8e4bd46c44f071cb3ff0e67e2e9b20141da32b064eb4d04f0389edfdd81ee3cc8b107ef524904ce1dbea63dc3a0e4ae9cc4581" },
                { "ro", "bfd5233354b94e59c8c84acba9a1713c51b2d06088f7568ef516cdea6860675276d2fd2522d44bfdf03883bd6c43f1c688bf2b6f529d3cf257db15427eddf110" },
                { "ru", "fb4bedc460c2145dfca0e8d4208cc7b3d2a93127ef3fe35073c923746868ca94be513c227ab02181ae25e6290f77f9305f65e9cb227343c1e24f275af8afe391" },
                { "sat", "d501559048dcec5d94a7f1bb6e3d6a5b4f2c3f7c229c267865f2419b296696f1d0bdd1c0f2a51b99f7bb1cbb6c77c0b6e315bdc5090f0554811e3e353c41ee89" },
                { "sc", "cec4fa128f4bf58970d0f6e7075a4b25fc9fed1057816385d392e3981f38b9e930bf494b9327f20dd49cc6b8c023bca1519ac22c8c3c07ea05acff08528d5c36" },
                { "sco", "2d6fe6b781f6a09bc79984abc2d980f6096f5da532e87f0a8d3eee4d848d22d69130adad32657aa12013ff4e2e1236e2e72b1ab0cb837c79260870df015c17d2" },
                { "si", "e2c25b438cfcca228f5cc91d1d601779fb6f59471abd33c8054f78d0aebbc22a843c960968c271d324be21116451a42b477bcb4f6f22da0a190f98c2b2408c3e" },
                { "sk", "d7a582df8aff46afd94a99d9feca24ba676fa28884d79b5d3c2c8c2ab5dbf321ed30f59b44122e44d8ea8f4b8ba8839a7b8b918fabfbed925cf792d12f34f0d5" },
                { "skr", "5d69d0aa9a498e939e69dad1d55b9bfcb774e150511d8ea8e9a8e9415f550ec2f77cf2546a87be6f03a3842e87c7bbb505ae7a942001c82b3ba4fdfa74eea3bc" },
                { "sl", "90adb0ca93b82b48b5753aca4b13da38d8ca5ee3c03f5584faa2bb07e2a523fe3b73756344f980357ee0e7ce26653bb55f4c0321c8d985d9e361822a42344303" },
                { "son", "dd410f3d0849d0f97a2f323a0439baa47c11ad2e58f2e7e5b6d5091088eb91a604c41e6dc4009c556e9822dc4f08e1c4d0cf506290ac13d6294c603edc4b1151" },
                { "sq", "0b4169183720892148ebc24fb7c2f73a3de5db99f2c33326d4df65b89349acf64ba594537fe91c0df2ccc7d0392c5c5dcaacf860163b50b890a01d20aeb8eec1" },
                { "sr", "66c849dda757ebc79aed817afd9a1b4f414ff8af3dd9ebed99ac44b1b679ab7108a942bc84c32811e2d4e469dda4e3046f1defef3405e46aedbae5866987d38f" },
                { "sv-SE", "ad1bc6c21bd2e28c21186fb728dad9b9604e7aeb828215636ad688f9171b9877fe9d8834fa571a8eb44051a3dce627e4f2b9697d1901abe35cf4b255756eda4c" },
                { "szl", "903df25b3045b9620756e1fe49726892c25cfdda17dab63324ef36ba434e501c112f633301c6563dfa6eeb2a8c34246d0ffbbbf28c6bce118904767cb8670373" },
                { "ta", "f1eef3ea7417d3b73ffbf30471d4d26c8061cc39c463ad8d5b6a4902ae611694df410a9e9b54338c1681a58b8d61c892f0a90f13363fe1ed20dba2ec762f330d" },
                { "te", "c73b9d0035cbe8def60a879b2757b745ff9b9a459ad8ba45b64102d80fc1ece4cb5c56f58a729c43acad63df7f7efb539c64a98288256ff881333b153a7107fe" },
                { "tg", "5b31bd2fa1bdba07ecd26c5e50f498dda92b75f7e7a54c6bdefd0fbaa1761ce6b1c38dc6e2bb81d10be4fed634683f2f6d09dcc580337aa3fd0a1ac0e79f0733" },
                { "th", "ed13755d376cffe6caf842a48205c90df79c3a9b90ae6323391ec0fd7c85b8ad5dce8be306c59ffa11b5b20286d9319b76f2876e98475185f44c6a3bc29dee58" },
                { "tl", "2f1ed1c68a73904c54dc30c437d7e3849056435b032d224d360ebb18d455ded95b6f3354d57e36e85db10dbada947c5804211adfdfffff17d3b9a5b1f3e9401e" },
                { "tr", "097f9b7f0224f0d8c9c8812c18a91bc830212193802d6d975bba87c48981906bb600ce12ab12a3d8fc731ea6a50c6b108c555730a40a220981dd826ce54a9350" },
                { "trs", "34654eaf9c9a681c803e69f613919c1a1650d7aa7473de1a1694c5780bf3111d2dcf42fa4976e705894fd19929f740c3fbcce1448f95a20380cf6fb09b3ec1e3" },
                { "uk", "7f3c1e7c133ceebe32cd7541b7b34654cfbad509ac51e6a9af83c76e760d3d9312e351e8b6efa0cf9b5c61ac4a2cc4067af8073576462a18d34750e7e951cddf" },
                { "ur", "b68156cb5115fe0eeaf2d4d81bb60c0fefdbff812dda1ef2ab06be7043b0a6cc8071df8ba21d96594495fae5738b6234e14c92bcd91e8fc4702f34699df005cc" },
                { "uz", "4790e0b34d5f106ed9d77707703c0d5f12f2f070d8a8860959879e2ba60a7badabcfb671c9a43fabe36b4334543e898c1fd710e3bda6264789999cdd5f3ada61" },
                { "vi", "4765ede75ef081e094be57f1ad5bed80c524a9e99ea5a10de0f1839fafa22041bda1bfaa3a60e5f05cb4f77d427cb8f981cf7532e6c2ae2f8abaca541d0fa0d6" },
                { "xh", "456ea042fb3c88c39df6cd7c6576cdd0d2d7340fbb6ebbf677e18052d8b3df7d1474012c8fe5b08eb958f5e4af8a5f384a0d1cd2f8ac2fd3cbb650a2d0b83139" },
                { "zh-CN", "21de1861ba51e9ba16bcb0cdfe8a9a64b7d8a75a5c438217a60b43c13c8cf8bf10c654fefd54b2d13fe3caf7dc7255e4f8185239018469c58dc744a2ebc1e2de" },
                { "zh-TW", "5287fb360aa2468a42eee7694714ef3f1a42f40c5416f441a0b3d02437e305dff6efde690a4307e0f6e30b47eff4cdc63bec99ad506f845ca61ce023352c9a6c" }
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
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox-esr", "firefox-esr-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                Triple current = new(matchVersion.Value);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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
            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            return [];
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
        /// checksum for the 32-bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64-bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
