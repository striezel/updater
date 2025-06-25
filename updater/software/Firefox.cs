﻿/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
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
            // https://ftp.mozilla.org/pub/firefox/releases/140.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "135fcab308967ded54bb72819718ac8e75ae8688b630bef129acb8a4ff042ae84a20d056b7dfff06c0efbef77b0f3776a000cce6a1795f3e3513fd0ad2a87621" },
                { "af", "f0987cb3b00456ffa9e95f21e6a893f55f855feab42474ef04720324f76b28a8d3724a00feeba2a74b4c11709f3a80a0963b82e2e44ad1eaead30ac05230cb39" },
                { "an", "7e0756f4a2ddccbe76d06169132d1cbec543414d4562520a5ad14dca9773baceb74badcf822a0bfb88c22c9798eaec3614564528269dd7703845e4ccc0f96b97" },
                { "ar", "895d0d00321aabf5b4f48a3d53bd72c8a52a9f0e6077ed1b1c6e297bd7c6a6fa45ca7c5a1d03b835a72f6198edb55b930e0b88a4394d6b76c8d1c8b6b1ba876a" },
                { "ast", "969bb407f85843ff2b54766998a66d75a2c4ec4d30d4f8d1d5e874d2bd69b00f99099a5cbd67b0d6490640170a31e8050672ca07231c355fac0356042c68c5dd" },
                { "az", "78201bd22cc47ac652fa8cc21720f8e143e511893e210a9b2e20a33913ba81d9586073b61c2e74a98ebedce735df08c2e492daa74f31ef334b9f0a672dc00451" },
                { "be", "08c9e964c79956112f6ebcd26156a4de3ec14fb18ed6f1e7b4f56f9664cfb4a8031cc18a8a21dddd5f2597e6692b1c34a4415c64dc373a1593123afcad5e5d4c" },
                { "bg", "4c6faedfc825eb7ed92ff625904362587acb48aba2c63b361c8c7844008ded4ddb8c570011ef9cb6a757ee65c9b4c180a9c2d04d327824d8d983d9529814c3f6" },
                { "bn", "b8fb5168915e982012abf90de0210b749fc583a405f02ef98b20717f04f560df7d1a10bf2fac0421832204bacefcd2d9a4e7db7f15730b4b55d12ad4ac03a506" },
                { "br", "cdfe846d113eb897291b961eff66821065bde6c21a9ff94ff4f8e0f8a760914a58336fddafa46917615135da15c158641bc9d174541fb640c3d4c19729e6747a" },
                { "bs", "05ad3891398dcb2a1260c40a29a602857dc5c368adb38fb497fa82ff5b774fe7b5daaaf3ba60c74938ee44ad9fe18b7b8f905e4472b7dbf894019e39182550f6" },
                { "ca", "e0c1bb47c1f03be67b963c36d7e8a307a13b6d543bfef547f3f7f860f0416e07659c99f2b02045356e4ba11ebfc50ebe2b63797a7dcfb8e58be61c405e2d5bae" },
                { "cak", "2b2040a04cd5ff2ef4b2c6d2b56f04930a3f1b4bdfb85d57ab6701c633015427b72062c73556e20ef8fb4969201c36e606bf88fc6dd5952d62351b1fd477ed84" },
                { "cs", "2cefa4f36fd8f70e0cc9e759d5e19eb11ff298fd9d6672762120dc170702b169b8d4a549d61cef7462da6db8fcd53d8f766f4b23d8a8713ea7785aa51cb9d9a5" },
                { "cy", "0b4d4ec7398f2f3f4d56656684e9ad47e642c2e92263cc7bc092d8238e1a03c3bde80878e90df1d2244399bb25979f293f49310fb9b9a95c0add485f4916d759" },
                { "da", "cb7eaafe1e2628df7c37c049cc82769ca75ede425e70de5136cc1cba59a0ceb7388eb0ab5269aa87206c75f30721e398b69ff4b8bf689705db7c2fa930663558" },
                { "de", "a028ead917bd975c7f5a00d811e46ddc1be9aec5a6777a78ea2470f300abfeb81262dd2ae72eb05657607e7481e1ae43fc6fce221054ce148ebc61f4c9a7f1aa" },
                { "dsb", "d64996d2805300bfec2d28c1ea9dbe22c5908a23a0fbc6311afb226ea3597eac337b0cb4ebc6be4a1500c695937353c23b6d78eaff776ea14d37fde59f6cd43c" },
                { "el", "c8131346db207a5d954c2862e0bbee9c6ad880f47e2ab43705a843046cd2d8a9eee2280aca8bfe453534f39e33f72b3993c66b69e0dbe9ef51e23b50699a04e2" },
                { "en-CA", "c1a85b53c048e55db6d64d9bb8d33eadc1fe7809301b9725803dc22e42b04d10fa533cdd723d02e0f04dd76f8a337e13b70379040982f1e5b8aed44f103016b5" },
                { "en-GB", "f03059b80b2d76b2e6326275d73b39b8243a5c31475f832acacb7d2cde9bba476f22b2393652750f150644bd07c0917548c8cad0f6f8075f9bd1037f2261388b" },
                { "en-US", "606671a7d6d7eb0e35ae1378185bdfb36cba96b8d68969a4cdf93e2a5a542c3f2d0460e7e40da46600c365e4edf518be0a1c6be9ea884097d36846ab7f11cc72" },
                { "eo", "83dd3fd95d181cb85bb0c09a4b63c080692e6666b48682bb5def801c9fd1a5894a800f2dc39238d312f9521b219331eaad224daa47ea262a32df0415dbd771b9" },
                { "es-AR", "0c9ee7489e3c52d79f6602583f0ea681cfe600bf06619e34d6a51176c4dc427be3cd1e92fe471475a69e0f755aebd73b81870e0b29d104ff076c3680e83e2854" },
                { "es-CL", "9ed699302d534e38e7944df9d346c75300cd9682cb84f18ea2c65aa2c9fb749caf88ea31c4765716b6e97a1b4c0745b8173cc0921cb5ae6012442193357719f4" },
                { "es-ES", "6711378ab7dc4e6eb2f4134180c2e93b13c0c533b7514a44dd2152d5a4f2bc474607e020b0d049368700f551a86e7fbebb029631189b1be3510ba92af38d8a55" },
                { "es-MX", "e8a5cdd995497710fb35f16e2e7ea53c3b818fae55c83dd4a923769fe205f8371b3fbb7514dfc86fa4cb72e7829bbffa938e00d1619bc9cda1df2910590b6f22" },
                { "et", "25833a3ac7902545ecb298f8adceb761cbce800d34056a112247d61d2ebc2a3dbaa35b2b29e5cb1103146ff3bd0ef9a7962fe77fa0723026745468606528cd54" },
                { "eu", "67f0e3b41368b7ef55ca98209e59c9056b50136d4551e105a80507d228f0fad7241d7453b5e16dc187dda3aeb7ddca2628554b6912fb4a2d6f4630bd57f8642f" },
                { "fa", "08657966f13eedf610f53dc54eaa27e8097834f53d1344b5d10e1de33eec2304803dbcfddfa3c6cfb5adc42ffa5d98a3bc9bdec4a0d334c78687754a425f2757" },
                { "ff", "f42cc1e248bcae3e87a4971f600109223dfd26ff8dc44d133cb02964a81b55ee991f6d0be7cd6b9866b68cd14516ed67990f50e6c0546685f389da34c6ff551f" },
                { "fi", "5d578672846729fab66338e14410576f5cbd61222ba8ce1b7e8f0da1823dcdcc2cb5438ef00c788263dd80a852c842cf8c64b66ed65fba005898ed46839e7f3d" },
                { "fr", "fbc5b3e548cc8c4f22af35dd92bdeca2d87331137818b3b8ebaa436c7b7ce6b4bbd60d44324c4c1d887db798814d99be041eaf9d4fdfe9c102b47cdb8f67b9f5" },
                { "fur", "18b0208b2106519c6d8433bb6a31e4f2a9e4414f5804788add653a0f3a17f41aaa276d782380bd1899da2b25e9cda866786b68a066384334511a7c1c97701cc5" },
                { "fy-NL", "50424dd7ecda76b36352b1b60c6d343c6208ee993b1e79da894f55877109cd91a0a68f450ef33e497a3bdfbe0da2bb4eb3afa15da15362304beea6e8f46ae919" },
                { "ga-IE", "0ebf204530b3b239a9106920c770b01b7a12714c0418a01df2350a29e324c0c6c3b39c85b79f17d625706014e84426ef5789fd2eec1066b3b8d5c6d557ba5ae3" },
                { "gd", "2767e86e5d59a64dd596daa595e1ab99c3614df3cae1b60d0fad4f951ca28cea07711874812e50411b50bc1101b5ba7bb9c22d6c88b38361e1b1d8fd6314e99a" },
                { "gl", "e68053907186da1c777e2947d42587f9b12bdffc51bf8966ed524f9a308372b4df30a6bc5685c15cb137fd5ac0d5f00cf4964609b2ab60aea9b3232b8fe276f7" },
                { "gn", "1bfa9ecc5c64d00ed7c7e9999f04e2052e0f68ccb5d035eaf3d49bf8ffd6d40ebca35f59e8bbf3fb6c7e90800024a6fb414a0ccce3f3d99981865915a204ac91" },
                { "gu-IN", "2890529f130b7a0e1ed236091d72aff60a9fef24cb7b2de2f5f85ee72611b44a6547a8d19aeffd5dc6fada17789f249415987ce1182c6d2e2ce43d9077e3f19d" },
                { "he", "a4225d8b319f5f8fba4a95383cf9452e4d0854770256d99ee38611db1ca3527f8055e05d67fd3e13ced213ab4d8272d9ceb2dc4e52b69b0346585655eff37a69" },
                { "hi-IN", "c07f5d60cc30a099099423010dd8ab7c00d93bbbfc43ccc4d2d84a731cd7141d778c39acb33ad4011c71b65fe967255855bc60308a0035d7d413a54efae69b32" },
                { "hr", "1fc47acd5159fa0c050762faff7f985d77127874c12badcfc9ba9e5f6194ec560b300c95b188846b92dbcf73220a27afd67373d5702623bc3d59f8547c9051fe" },
                { "hsb", "51e48cf13440663097c41aea5de307ce1e441fa73ac8a266b37285bb615801618e12feca9de40539e9b833361a2b9b75ae9ce591fe3e350b97b1a4f906447c1a" },
                { "hu", "2aa3bc655cde3c04491fc960993f85a288129aae0a3b4189f29ecfeab2f7d263fadd7971f51a9fc222608a1f35f3ed53101ed2926391c50b0f7152b3a2bbec02" },
                { "hy-AM", "dc5778e786344c102a890bbee81e985e3f708219b5140f0cd4691e85b8b3b9ee6415f396adf9b64d141a1cd7cccaa74e60198996532284f7bd8bece2984cf172" },
                { "ia", "e2640f149cb6ba7884841a0d48e3ba38f1de02684b1f467cf79a9316e190dce17e854f0491f1a03131d58bb9c92de2d90f505bfaf93ada6159002f42a7e13ca6" },
                { "id", "ca9acd0a7d796a63d3fbecd238043cc47f270c18ea6f89835d12fa3b9bc8087164acada2aaa804718f53c5993c3812817a52145d79d44e5fb435763ffc0a8c87" },
                { "is", "43c7cb1f341b28791533bb1523844446788865ccb0179ba0ae0ca21a2231cfb7f6ce5a151b5a2373aa168db7ce4a4c1e581ce98e8caed7ae934da80e55f67a8b" },
                { "it", "e5f18997a95b43cec4de2f145df831d1a5efe966f653989f780474b22ed31f0d9afa4f6cf91d6129c67b85f12764c822bbd919c6abac41de0ff525de539f998f" },
                { "ja", "751d86a7619a3655f959996e839e37e5b569f63cc7b311894f81d01d9b91c66fc1d34276eda7f3990c346e75c09162df56a6fb4c5679c16434d613daa59c6644" },
                { "ka", "5e3a5e43ccf0e143d846058dd5525aaa8f1bcd32e37907ba12753d6a1ebaeb7d4d15a993d49f5dcd521e5eeba0f530952b8ff3a04078ff13a90176fd4108c9bd" },
                { "kab", "760537ecf958602fc91d7477fba5c8535a0d37e8522d5acf1e37bfe415663a60b3f653ab1b24b1cf6693d814c3ffdcef2f602c3f98b4673f776a1297a1dc776a" },
                { "kk", "c2bedf223d7be652c7a212b08a21cb6501cf82a4b6bd5df0886df0d1a830f5f7999c14efb8bdda6fff84a036aacae12e3af2e5b7b200331b726eb8eb38192f14" },
                { "km", "8fee218f1ad475d68ec2c3c1e4b93a7b835c69c737bfd5bafbf2413584fb7088fda8941c325a31e87595b775c3970a1aceb412bf5c89c95af2d01ea25b20416a" },
                { "kn", "f214b7c056679fcbf65ca683cabec419238040bda13ace77c501dcaccaea5cabee7b891fa91fa43231bb00ec0208e7c50a33f9caa688fe85f3c0d1e0c94dc3bd" },
                { "ko", "18ea9f1ef4057bc06d4582459aff35d9359597e16dfcf3dfa554b75f39dc92ab979a3e84a05399989775aaba725c7488424645987cdf3660ea5834210f853bdd" },
                { "lij", "a98aa1e390fd8945862ccc438d6e96596eeb14ebda166dbebca39b3e753355be020d5b187ae0c47f853e77837d3bda531199573fc6266d9e43b97d257e1b45d4" },
                { "lt", "196275cb5f9fb888483640d3f7f1c7fd426d24ba6a7daae13cebddc8fa616f3b2519a141889a591bd3966a4f0255ee9b0808d450461be8ec6823f2f8e9726ac9" },
                { "lv", "fabc7393d79faca58e1d00c5cfdd29f3c70defbb74c6634595f959295d7b24c72049c917ae7fa278717a782195800453f1997931ed0a19af571e914439d13882" },
                { "mk", "2f870a16b4399194f9e44e6c3423f9814cd9fa4b440a077a1048baca7c3f5bd1f3cf3c206c136f728db1f3c820be193405047cee4b4be196b2a7dadeaebb71a1" },
                { "mr", "0736f74282a02d6203273318333a0eeb5ad6975f9872a4dfb9f2707cef19c5311eb9041eb35c5a05d377c1c19772b1854d0476bc5baa758d5110bfae3c8eb44c" },
                { "ms", "84de14e325a81a3ad8d30d8618499fba69f94389ca85e989235656bfa0a141986f182a9b3d284c9b4ae6328e3ba4014b0de4bfa8cb44120a69235799ab14086b" },
                { "my", "6191b781a3b0359c26619ceae09a17af4505e6e0e5566122c04f4255006e8b7295dc6e29c6ff3c78f6dc54ad432fa14479c0a585bd0d4befd2da388f67800ffe" },
                { "nb-NO", "93890855717588623228d76b068cefcd11be37a14a2a03284a7b75d0de05588af97ae08ea31b8a3e7e19187389b7454486b789740c59cb8b36466b67fb5a505f" },
                { "ne-NP", "8934b4e98911f27200260d7e9cc95b8d9f991ce5ae6e5af1b26a065ce237fcab4c867af9d78171ebcb3b1c940c8319677db10d59aef7a7549c9728858e81101f" },
                { "nl", "3bed9a07449d0f1ea35e5cb514f365411f0e6febdf40602899e202a5559eb0a39352e047d8b0ae8d16bff19e4a80b7a973fa3182d42b7e1b71e2ab09ab18b362" },
                { "nn-NO", "b708ab9179c8ed19256fe5417b37733e5482be8f2c3d7851d81c14cfdf0ea71e6317c496beccba41a16397cce4645fba19b4643db8ddbdb2950e0a1d0b24852b" },
                { "oc", "5a7cb774daff0993c1adbe2dc2147debe1f995d6b793d1679522ae43748a85914f5f3dba26e0a21619e0b000e2cf8b15b552066b427879afd0bf9450ff1b55b1" },
                { "pa-IN", "85c5a35f56b82a4fd81d9beda4e10c6b22485a40b5c65b455e8147d33047a6fa1df95ba2d4f6ea11ea33f4f3af807a85236d9e40f5e064a501f5b1b83a22e4dc" },
                { "pl", "f9fc258496f62ba999e8464c5eec9668c7bd404b457dbe8b87ac201fcaa4c88177f8894aad5ebd1f21ab33f38d7b9e04e6be43b4273a0f67de98f77d2da83e04" },
                { "pt-BR", "41f0f7db50f4c80d1c4c8570c8acdc840e6c263dc87f7bca826b61ac182d2b3918c17b79601b9b14db653e891124f53d3e0dd94760e642505027a8642fe8c29a" },
                { "pt-PT", "dd26c23a18a0042afb59ea21485c77caec43c7763f4f94ccac1f5ae21ebddbed70b527349b76f42ceb04eda80354db68292518a4c1772e3b5ce18feacd8d593b" },
                { "rm", "a8d611156d84f15133f23b3a3333ea0f1bc79c42cbb9ef26352174f212c94b66b4fa9dd78c8f8c4c96de95325ee91de28adf5197c0bebade323f01ae921681d4" },
                { "ro", "ee05d3af7bf1f93f1f46ef4b07aaaf172977a0e40d5ba2995b72c841b818c9d8f928e316c96b32e4a84a0717e96caf509d2259425101626fd4201423ef8b9186" },
                { "ru", "4a0264e2d0a7a842b93c783cfd587bdf4583d9dd9f7d5ef0f211e1a4f22fce12cc0e93267ce37f8a16036f636c872483c7bf2f3e17c651e863ffe9cf017a1a7d" },
                { "sat", "79d3f1ae3fa561f64cda8827129059cbcfd78a503437cc987672fb408a8e0505620627a87376eeec665a01f03d7254bda13e188be753c96754b5fb2129e23477" },
                { "sc", "9e1332c89f73466ecae5313c1d5b512266440ee3d450bf94369fd6522791acb017c01e697afedcb26719697883c4e19c2e77a50cf984b182b5e6b7f7b47cd797" },
                { "sco", "0823a91a7c4042db29f632de95982a008bac95078c0ad8e38d0e863fed8ae9151f9e872d02df8b83174ebf1a568bb532ce26e9ba3749da23c576dcbb7fa16cfe" },
                { "si", "08bafc48a4f2aafe7698a4d975654b84d04d3edf5ac997f628b58dc03b7237bf1d5cee1714a9512bcb90b95f2ebf715aec76d51199644851a13131a4b1aa4098" },
                { "sk", "fd34b63a783e389e87860609026220b6c89e7d61e2d6820cac5ff316ef69968ce4536fe380787898bb3355ff09baad4e9c279cc3bd428d54bee12ff5d72e4600" },
                { "skr", "781ccedf282010331472ae30a869dc94d1f85267c029a96312551990b9b51d00c287b20ff1470140b16823c242f77d6ca18e2616b5bfeed118c96fb3d10b0e63" },
                { "sl", "d23af671882b91fc7b6cb16d14e54b2d766e56543b95f764bd1a85fef9359466ac18abbf54ee3460123c7494f8ea544f2b584177c70bc1252928ea1bb4a43478" },
                { "son", "feaa292fa47f01d616eae05e17231255a4f90273e0e3f705124edcfdf8d5fdbda4cfae82b8ec97a28155350404f86fa39e93b3fc2ebca4d6b50a908f4ab9a6d8" },
                { "sq", "fe25a4bc6ad0ef3563f588dc4d9467351a1047c1638579a58ee731f6e4ddef81cc3c975a4ffa071a88be48b8aa15e15337043157f4b5a4f3d7f6333f05f38d25" },
                { "sr", "a3a37fa84f11dedc2ac6d8e0cf2924173f6eac5fd4da688f7726bc1e5958a8c76ecd0dad2d7305a2235742db28b09aa0abe9aaeb1b69cef99b56ecd8799ea1d5" },
                { "sv-SE", "6dfce5f4eadd3c8e68b3d778c15f44c96ac1c0c25cefaf0084740f49fd969705c04aa310bc48a2bd67db737bc69c56cd336a10ba743a9fa4042606555038ccde" },
                { "szl", "6fbd6e852ee052c2b996d224168ace0d10cf861490623abd1a45cb9adbbb2848f56c8d509c07fe9f03c7018469bf6bb30c61a4c59c8ea2b895d34b33efb78d4d" },
                { "ta", "ae5c42df950e61d568a108effdeef8094c4d8c6a007c4d1fe3efc1a8165501f90faaf70dfe52c9bbf7229cf03bf992c5f675c6759ee5b43841ec7a26b9c8cfe5" },
                { "te", "ff1f2fa692ffdd25534471705aded834fcf7d3b739f04d09f669d7b26d97b514bc93372dead8fb1f2cf5f0fb20fb37e1a761012c8d741accdb6fbf056c2a80df" },
                { "tg", "fddae40ad0a50881759a1e4bfec2a013b7e36f650430dd0828218dd165b825403c81c6505ed808261fa364227f9bcbf0ecf505f9fc224efb5be534b4fa9c36d5" },
                { "th", "ddfc91aa037c69b25462f5dea7041ddaae1279226133b05b1e8f5af430993902695f63b548225debb5cd807fbeb3ff765b6c423114b9ff61036f3386f299751e" },
                { "tl", "89aadbfee6b2cf5d6a834fdf85aacebe4ed9d602a25d41f3137e5fd351e0a292c60470e175709877b6da235b900645f679d9988547814c8a4237259900adacd3" },
                { "tr", "6cd85ac502a44b5d08a9aecf4ed0d65c83da76cac4658c603c94b7260725637b99d8180394aaee54d4f0dfca138561d56e7fa65470b7cce92373336212fd8b77" },
                { "trs", "31713002ccf2efa35888269a53c80e28be012df595f77162753790789a46eb8a874b427596c8bd1b74f4e4bcc4a590670e1f77da131c7d30794d09254a173713" },
                { "uk", "1e72400e9a5d1a2a0eacf85432791c3c61c2f706137a50b6e0cc02ac3c66ba0826c7b83a0a6973f9bb450879b2ee0b7b91762447d0415a64221f2fa6bf6dbcd4" },
                { "ur", "26b0760e6438a9d42843dc8dc931c6a3850630f436802b40b147e912815632e521b05f14a5833ebf7997600c2863acc9d9047b46399fb7660e56a65cf1f847cb" },
                { "uz", "726d9f5a14ab619d9f1b168a974a7526f8f66f3568f966aedae721fc89c75e97678f4202e4b484de36cba87abf28259a13148c0dc1583ca663c91596267a3e55" },
                { "vi", "e1c95cd9c6295ee0cf079310e4d6bb06eaf6d768ddb10d409f06c6cbcb8eacbdc53bcb4e1d71c4ecfc0dd87edb1c6ef293705a6e103652d7c55c9c6ff1c0157f" },
                { "xh", "b24fc3e1042be2473878e47eb14ea16757823395b92d8c6e8af5564ea71fc525e4462e7ce5f8c5200749a78235dd5feb6653bbae80e06d1f8566b83f805757d0" },
                { "zh-CN", "cfe3d14bdedeb52b4a70c7961b6972e428e511185155317663ffc83123ae9bec903caefe4842cefb3c820ff301fa51b9ee9f5e17efd7936c86bd569850799bba" },
                { "zh-TW", "8cbceeaf8b7f4246fad9f2424275e5c72d38b33806f712f4d8e5038f731c89ab0fa75dc8b5b181e42cbb6002a3774cebee275de6fbd76ddd2f00ad69bae679d3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/140.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f9dcd35d70c51ddce5d7b026cc6c5e7e2737bb6f45c8ea89343ab8e73df9b29b5e6d216465b879586d87d4694f34eb00827e181f15fefedeb1ff93cfa8803764" },
                { "af", "0afd030896f17e1fa1169304a7259c12cc5d3a787b0d1a536ccb3325e2cdd6584e8fd4418f8cf87a1fd332082967af76f2ef36f83da628ae8f8cc3ccf42afa13" },
                { "an", "7b53c7b786f5b7e2d2abcfe24a3abeca80cefd93d50cd6a7ce6ac74ba3e151dc1229e8a5a811c1ed020a7e84717c2c4ce071bc6bcb8f2f28cd323b50349eda4e" },
                { "ar", "4a558351a63df795b6903c94881adbe6ef3383ceb680b9404b5a811f3c7e7d2ccbbd5ef3289dd30a7a96364364dddd03e2777b96eeef9b3c318767976643bcbc" },
                { "ast", "38a838104095e28aa6ef44ce8da9e4830e4523d6f4156680cb5580e471d4ecd87848b12917bc43ceb0f6eb7c1308d65f46deb3a37c447b58fe4d8b5a7c376d55" },
                { "az", "be7ddf965605aad042bb9ffb36dcaf1e4f90b36f42d7c82d0444b4aaa7f0cebbaa29b48ef8634b488fa914dbec08387dd515182c32ec8a012d19d829dc2f7708" },
                { "be", "7949d3df8fbe719e2efef1b705dce37711cb026837b8bd66a2f9589607bd5f2164eddd1b24eb6b90469871b3f2706d4826e8bca4bbf716d6db66419b63619bb1" },
                { "bg", "00d1a935e562a2485faa91e6c4c2b450c751dd2f19909a1b452426272f7a004a57c0c8853a0893a75dd9a6168c37f8a1d25e23e4ce4dbd346777f36f07675072" },
                { "bn", "f7571c1038220d1e73cacecfbf074327a39f44e6e3100c1c24d8d530586574b27dc2921f604ed3b16446a6f5e67f7504170dc8b8e4cb8e8daa5a9b2ce659c2ec" },
                { "br", "9e77587cf2ae47196a2abcdbde44b6650305dc64290ac2377ea93ee14ac673120e30e189628748802a5ad6876e115aa1f7b9195c8ce6caba0d9815e6d58740dd" },
                { "bs", "f679151a980c00906eb1e5205696b3fd7741190cb23d7872f6f851cd5ad60ebc60e8f15210b92aa0da4a12036b60c4a5422ae73a2ef7d2be71a5c832703811cb" },
                { "ca", "9c8b3acd870db6b8cd8623987aabafc1abc1adeb3aac3d9868f77232175baf121fd4ad2831c1992d78e2e4e967aaae4fad8ef95a77805ac592f4aa35980a9500" },
                { "cak", "fde8ee21fc73ada5f3abdd8d9067f8875c814a1cd6d6e5899daff6b66901430a4103fce27deeebdb9dfd4c27f0865198b34c3f3942a0a1adaaa61a4b6631bb9a" },
                { "cs", "d4c66b3af6314e2f0fa1af50dddda2fff2bbe58a9e05357039c75f20e3801fed3e6a18ee16c668f7e6fe09aac4463700674969c0886b632d55d2f041cc574bba" },
                { "cy", "fca8c524c636a28de99e28dcdea4c6263ef085701c0da441efefbd70a69cc50e0bbc1f8dded67c73a437c90155ce18c3a02002c080b224c7ba39dfbcdba36745" },
                { "da", "923c2160576b45a42e989bc9cf8e6047134f023b3d99aa42d277454feddd82e56bb6f14018e2af1d04156997a209cbbee120a6474f0acf96936b76a055e9627c" },
                { "de", "6a7cd328ef30ac255c709b6e69c4d8d9695f23ab4fe3f9159c35c25239445b0f0f698d5d45614dea5605afaa0d94a3f48006fcb0d2d8816207e41925960ed0d4" },
                { "dsb", "b509738d7cb3e4e536965272c3254caa1fd48fb11fe510bb4c8c13fe705185ba4c1732e5ea4743b7d29f40d879028176ca3f4603b9c69fe9071225f4c11df8f4" },
                { "el", "d2f9497ae037ae5352be42259251c5c3e61f8ae010782e870356455c22ae067682467b87994becd11281e36acad58d9fe3026e18d0cfdb626016899323f7f318" },
                { "en-CA", "ab8621c9c3ef6dd405b07ae5484e250faa7b2723ff8129944d86eca4e0f48b9b7c0035328be41b22fecee17f47bde162fd57f8dcfd1fcb3364cc38ad041ea190" },
                { "en-GB", "8eb6a5b9adb51e3d975ff1d1b672b8080e2821d9df33d7407be6d3605d8a4029eeb797530ab699b430c4ca3110b908d58d5087f588916adec2b2c3979ff8e6c2" },
                { "en-US", "fb0fae86e8aa375e447613d48b82f36b4f87d1943e0f6aa26a21c6a352d70c76c7044f32ed345a8abfbbbcb9d9fc74800435dcf15903137d5dd9655a46762982" },
                { "eo", "fb64ebd7a3416641dd56282a504ec13e16c24282e801e5c55acc231f2637465804e4f10fc6921f4b17f708a8e8dba3dc9d2617a1b0562ec785d1ecc317c2c4b7" },
                { "es-AR", "dff01f9d090015080f71305bb21ce34754e5bfa0dd6a47e90346f9bbc6efa178ed5ad95e664ce393d36b17dfc006d269778a4a7e0c9eed3af1f45914f8c96837" },
                { "es-CL", "d611763d2abd0b4e20401917c51ef2975da59cf9dd2b0e2ea2fcffc5bcd352bf9b9704b488a3189f28cb1b8a18de8625d7c9af92e21f936ed85c2e06688b1961" },
                { "es-ES", "49676bdfe22e0ba3c3573afcfe99dfbc824d0c8177c4dbe9a60040f0e9b4befcdc4766604aa020f5394aa8ecc92220322130d0a0d9f0ba02a6a60ee4d6956543" },
                { "es-MX", "76c2c10b9482f2a636d9a7be42da8a7aa1478483ef000811026f89b3796ae81dca16d3962d9ce2ee88afd1eff1ebf813937020ec0ff1a6086bbf025362c0c453" },
                { "et", "38648401f40346b1f1cdd37a10d95b567a97d9757fd04919d8c0807cab450b895dc4dfbc5166d6321fc863a1d79d13981026d7d626536bd0391997ed1f02851e" },
                { "eu", "63f846a8c03356061744c963b81fc9df76825a889c4e704dd381ab80babf5f25ae71fd30617eab50846fba3573ffc56fb97367504d800b8af138fa6d2b21cd68" },
                { "fa", "05d399a98a23ec0c3d7304fb7bce8da660a355de0357f34265c2fe7688657671711eec32741e843a8f27cd52a7a9477847c104e4ac5721320a0326e8160e4ce9" },
                { "ff", "12af0000f5076b2cdeaa6718ad0f39fabd80b325d4d6560c2b97b0ab3c2cbfdd47cab1c860eecdb9054c13e6fb337a28c4ece5fd9c236bb1e07ecf2b28bc5c10" },
                { "fi", "687d0d85b11c921dec62476f8c4cc0739ee00493d1d8ed156bef4a2c207df72970f0c4d30d2238d12ac3f2956cd2aefeaa7aac76839e4e989e368d3f8c55d5de" },
                { "fr", "8fea4ab57bcdf118c5d0761ab4998baaf1072167a6724bed53d40081a40399e46ad048f60ef2dff7b069396375ce52ccd57e6b4c2918a9983d0cb2d59af2ba25" },
                { "fur", "b3a48d47d1c05d59dca75d71b651557c6c4c1d774357024a574e4cf22b7e35094850525626418952b044db2928adb946f69cf4f77f58f886394c002959ed389e" },
                { "fy-NL", "bbe60bee89a21a0da5784f2f10c6ee5422efe4ef295adccc6a2bcbbf6470272476f9c2877c9b60da68e0705805c6fa8f63aad35ca4f9ba369789d8a8fcad1b08" },
                { "ga-IE", "20e1df0283c2ffa9491c64d60f3bda91cd48aeb3ec86de100908509fe46042e82ebfeddde263d61d5b8c5805691bff226089592fd9d5d46417f1330c26111f3f" },
                { "gd", "fb61dd6974f49cc043a4199cdceab60b0ffab033f61267d2b6419767f44b18e197aedddf3c0dd74584384fa7a330f650d0ca6551df4acfc5c7589893ebba70c7" },
                { "gl", "0e2169c4b167b3e22dbb38026700cdf01bd5d7f64168e5eba01af9c86ebce6474a2e837c635ff5ef5a94e2b47ac6eb979626d03bf1f9c2ce410e5539d2aa1f2d" },
                { "gn", "14ef271c6fa3542a69774a13cf44528b91c7e2108081b04c4dda7235c3001a3c32ed2caed36154a9ca806bdea277c5cd354a617d7812f73bfb1e0919cefa7390" },
                { "gu-IN", "c1f02d5a49d75c27a93a72b853d4ebb36219594e485226578118e574ae35cd59ae8cc603007e6e5ded0b88964211e85a0b95a1fd0891b3f3825db9b5011def08" },
                { "he", "1828a6666fb4069f3da590beeccd7456abd6ec0bc64448dc45948ebfe9b72e9ae93ee4de8c88b39b9baca2fd5e1ecf2e008f0eec3a88c97d1e25737dc14a3571" },
                { "hi-IN", "1d2634a08e76ac86817671286d5b80dd13052143dbc9374fcb3b6a46fa0f194d048b18b2aa0fb8d8345723bbc1699933fb5bafa324873bcd35d87cd7ed7c142a" },
                { "hr", "00df169459139e6cc129623576d6dcacbe5f98a418203837e7beab55dc30d6f1b92f39303b4914d99112c3fd11d2cc1b5ac365985ae54f6fa413b0a1b23e40f2" },
                { "hsb", "68dceb52ad6905eecaf0f07987cc7724ee278da033fd907d2e417f21df72dc95cda8ecb80a7f1555e4269bbe94ed4b7ff773c8c28e1b17cf6e6fe6014a68c094" },
                { "hu", "27050d6e0d4843315318c5151f4e7708deec09a7c9f3b8d6847a8718a0d2969938fd115fa7b2a2452ac374eb210856a4f82ee3de689ccd569918ad4ca75e6556" },
                { "hy-AM", "21383122f8c840f39bfd5a36ac47226264f259978184f6c329b434c806db5acc5d5811edafe1dc523165b520e23c7ac258a5321730e4ae28cf6c2b17f8a3a992" },
                { "ia", "592afae6ea032dfe26b0026bee014863dbafbce8046b9636ab0d9bd6a64360b1548c1d5d1ac5a4e1cfac438db171d082109215100eeba963d383f2824fd302f5" },
                { "id", "948fa318b459a11a942724bf9ff3ae42e0ac1e80644f9768fac16536d40268b790706b916bd4ab6d8353b077194d1a96c7bcd9ad8d3290d5548a5cec3a95b13b" },
                { "is", "2e74d32a74cea97027b8e7e6b13da0e6b9a14ce5fb4b3bd6b31bf8faa09fcf86918305f77583231c0ef6587783b428cfbe507c6bd3b91b1f61be60e7d81e2a80" },
                { "it", "8433809ca574ac593d84cf838ffbdfbf8d35589c1dff506714c49103bff931bdce627a7b9deadddb3cd5951546bdf83f39b241bd44313593bb0f3747f6687f00" },
                { "ja", "2ffb16da21ccacccf5bec39a221a9ebe9ae363f339c11691ffd1dabe26ccf4eff60d3c1530bbf307ed434d0427c999a0e7fd8fcbf15a9e8f834dae45354273e8" },
                { "ka", "8f2b70e04d0fc635c595c09aeca54a05b9596406324f579faefb50f7782f88e01dc943ba4366d5653bbf0062f6fff69315be09b375bd35804ca71fd9fc54affa" },
                { "kab", "514050310b11cd97db825bfa17bbcb1bfa0db87d5033b1505ac16c65d39c60d4cdf916ef54822531eccd7df6c940db97ccf51664e9cd0f5c6551146e205156f9" },
                { "kk", "50d6c1186299483efb160afb831115ce1277fba9f65f55f3001444b8b012dd7ba6d3f114270b01819a5969b1991024404e5a0602ede7b98c1d247f6f860f3d23" },
                { "km", "2e9341b4d1b524e56976fdcdb14770b0b6fb5626c7b66643e935183b00c98470440dd3cae5ca5ba7de38b417485d906431b48c83a4ac305ca3e371f3dca49636" },
                { "kn", "4d9c99556a071b4f8f2fc1a83f5c01e40e6c15deb8cf651914561cec48635a0fb1d8e3ddc5c4a57a9c0beef3dc699418382240693b1929a142d3b0babaa66259" },
                { "ko", "7e2f30ad17c98d00cd26f06670213da8b8fa5eb0f5456be1cf607a835f853d4a889b8f06f3eca2e119daa3cbaee574c3d28516b603298f52f8f2391eb7089028" },
                { "lij", "707b580f69ac9a5d0fac421b24c15a8693cdd51fc01e74a72178f8ee2d4198cc7089f06e7ae2e525bd3d2899477e4167e3f8c0f42cfac712fd87cd8e25ae2821" },
                { "lt", "3f57105194555fd85838b1e24647548efb9fb6aecde857473c20a95f6c8e1ec032adbf8d83bbaa0683659a492b6b917c2d29ccaae7891cb50305f9e432ae1382" },
                { "lv", "3b83feafd0bcabcc2a076bd2f15edf24d5b1825f95c288a3f634b111fc58ed6add3b5a5c53968d7ef87674212a458dfd8b4caad15d75e7b2f69630db80992a04" },
                { "mk", "efae2abf6700e753d2d55017bc1af6724572c5d0eb6681b81f03223c15f9328de9b6208c021a76e6351412d95e590751cc8cd2861810d368677d3aa5f6b32ad2" },
                { "mr", "46e40c14a6e407810ec9848cebff159f86984c8d0ee5a31eaaf9cea2f82456298d2ef857afa833882e0bae5f7cd3bafa18c9fbf2ca2233e3127158def1adeaea" },
                { "ms", "c1156251d93e09de2a5296d84a68cdb67d323e8d13c225b0ba3c03a799881d8cefcfa13f458da0cfd9eb14d912bd9e19c79ea9ca98a220ba206d820f86913ad4" },
                { "my", "73b9cafcbe367eb33f76a032957d2c1bc9c80fd398a0c70bc794384703e83dbbef12e381d7f339158c312e2d4d3c6bb84f977ad8f3b9e5d6af5969153cace4bd" },
                { "nb-NO", "7f5dc28b7879f8b3c4324eaa2700d711bfaa2d818e052bf1df85a0b5282123172adc1164fd51632e9e6287cb393a5ddd232efbad3c4e02aae27bd8052b628981" },
                { "ne-NP", "53fff3d52013e9089cb5ea48b7304e563176c3273aeffb7a78df0360e74670cccc1aa416219256e6d1adc1d13ae035c16d57d0094f09ffd2db6abb049e0ddaac" },
                { "nl", "05a92ff45c96d97bf85e7ca44b530194f2a4225c5e38c9f02ba25999d348a7841e8576886bfcacaecad6408206657765beae5e00666c771a22ecafd0abfc8fc9" },
                { "nn-NO", "1e6e49191f018688eb10db311fa85931e60d61ccc5be8228857be7cab0ed5a7ad59e55d29c0a4b50dc4174140e541a03a9a35a360eb86d31a1fccddb491f47c0" },
                { "oc", "6449bb6b8f0ed3cee3ac968fb756e294b1f4a3e0b413555ff8f53962aa3e8c2be00cd1d4a9447e3b9544e6e82d2480c6c0d0089fbea02493ab9ad87d44da9e9c" },
                { "pa-IN", "e1d87534d1f016f7effbdec234ed5b59c0d5d6ee084635ae5c8d8a6cb24f3c8d472b363fa55b022ab643b900539512a27c14eb6ed9468d7fc6b65d3abcf17981" },
                { "pl", "df2bf3f9755619e42ba2d28726218fdace9cda841c77c18afafb731736201545f3d5b1baa05438ae4183c7efd634020643f423d6c74e64d42bcebf96bed21cda" },
                { "pt-BR", "a19b947f1318382c75ab2c21f702555185b94d33be9abe9c81ad722d000b1ba86bfa7be36d614afc8f6b819b7acdf69e0080331ce67eade3c0270647c2ebb9f3" },
                { "pt-PT", "d6af33d315971bd7cefeca0cc89219567f92578772ef692ba9fb393471fcc7b593e5fec1a2c8238cf55b9567a155bf8c1b4b19d8438336472d1bd123b747fd0e" },
                { "rm", "cfc7fa8a65967af52d23585dd0348b56d9020d45e279adc5eb356140f133668d5db60880c87b99762ed771fee40c30c5dee1ff669b76583294db508b8063cb1e" },
                { "ro", "9300edcb648b969781f1d4de035e6ea3bb59d126b88d4d761e9d6d04d4358b61989b44e635c5e9792d3f6d8153ea75488bbaabd86d226cd35e7d007e2a48394a" },
                { "ru", "eb3d9aaa86b3cd9d6b4c409052723c6c05f4a1a4a4ab8ec65199169cf7edc930d52fc00977bf9dbe5de2d13ae3c39cb5ab5ad334e32ee6f78a6cb500055a94e4" },
                { "sat", "deded556c24cb98d2991c1b5fa98cdbfc30d3c02be13b40fde6225c5a11c0416524bf01352e40535ee8629712b2677eeda4334a9bf425550a3e399a3b7fb1fde" },
                { "sc", "aa77f7eece51ee65778e35faa4c3a9e08eb1e796e57fe72b392a9597e77532bcae8b257b42086d45e554d5cd1521f6a351bb124812600a37bd85199114a6f768" },
                { "sco", "ccb6ea336b5c5210e8144914811523b99922ce5eaee25a25dbcc2a6248888e8806ebfd85bb0634ca60eb5f803193cddcb65f768f861e605dfa83c79191636496" },
                { "si", "52f7a076246facfa6dc204a82ab64928235b6473444675b7ff9960057e6b93258eb246a4811d3a246aabeb35237b5a200f921cc0589d39cad91c316ead22db08" },
                { "sk", "11ae20c19a25b3c6ea149de9ba163db8e165170e851e4956b3f21245de7aeb5f57a855a9459f8b2001f0544ec8a2ad45af9a137f7dd901c169ef10b17b3d24ec" },
                { "skr", "93c619ee0a2be50ca29467706f27c5d3e0a6e91d79ff01ba70522a9c53f56258d61c0425936230d5ee528d725a442b198c1b8a696738934cd27e9f7c8a796206" },
                { "sl", "2092f9fa661f33e68b77392b10fcb8edb383c74cf5dbe7a0f6d03826624194c4812a203d399289ef53e0e3037fdc694fded923e4ffbe3f7e942ce21c2bb1db78" },
                { "son", "6e650b0c742d1eb192af50bc1d32950d018095655403b0655a9c841c1ccc76c348c6107378daf780bffb193422406e74a6bf0d3ab43ad99ce6e3fd632a7ae542" },
                { "sq", "b54e2e0a8e331a75135ce88a9bd3530faf1c9672ee3d1f849f6e88ec45fc44931262998ea94435d84554d03eab824925d911acdf74601611f48e067dd57c10db" },
                { "sr", "66c33ddd995e4901cc5f4301d2571bc894045358fc27614ab8463d0eb6df18129de656fb389b0f625386ff19ae38f43706846c6171723744fbfc7594319ea0eb" },
                { "sv-SE", "3fb5fba5fe7b223d503aaeab593be93051eafdd929b305ee1542f552a17ee0a5d74d9681e8fdd11129bdb0f12156f5c0bca65082edbb7db33819f02f8528338b" },
                { "szl", "7a4df251128f5ad2009752fc9a8aae812089c067c1af3512d3f16513aa59bccd8cbbfc4300cd94aa8150fd1054175116bc32c57b3638e758e8b3d0f546f451bb" },
                { "ta", "081c5ba44835c7305381e85ad1ee753ba0b7029b9cc2ce5a3c5f4566d56c732b05f695390d1eb355c616dfe1e4e4c80c08d38851444ee8bc4935aa6dacf744ae" },
                { "te", "8156aef3ed26fdd930cf87aef2e2cc1a976ce19f370cfe382a9124fddaa109ec6022bf61bc2b1b93ccce2c84daaccd640f98ca9809440545332657a68d8b4e62" },
                { "tg", "79c94288851db9941c7059164699300919688fe565336d32f27e2d97f51c90d47b8d05b13e6bf06a0005f31d10d10b28ad37e04f7b8ff2315d159c4a3355d7c5" },
                { "th", "ff6dbb55ace3fd3069024737023330421a7c74d6b469a8a65a0a212dccc4ea20e7be8dd977de0a7406c22251c13b9eee8b03d89de519fe5e45d7d3ffd2ab80f3" },
                { "tl", "606351d497bab6c1a1a6bd2b7c560bd7ac28a6b32de204d67b470aeac933141150272b111f08dd1aeb0fcf3d0f2f60b63a1fafcff7e3c233d0ed61a8c9445265" },
                { "tr", "35467ac200fba5354b0167474a30aa25d8dcc63e31cfdcf263e334aeb8dbf768d55988f94ad1b2d859cc6f7f9c6cffb53d9d95fb92ed2286a10cc06a3de683e8" },
                { "trs", "9b2034cbcf9208f89daa56c605ab89c38d45ec10925e819b962d4dbf3192a07dd1a28e15aab3c011dc81dda73e9b675c59c46276d98e834390808d75f68cd095" },
                { "uk", "ad66551c5b178b5e02a27138e87fac26e69022b0a50276ac740bc2ba0394acb5b0fdead5217fc1a6ff0cb36bd9d2b930d044f9638bf530f7cb67209d9afdaa49" },
                { "ur", "4ecaf26ede14a16505bd6f2788d9e028f4c6800d09c6aac0b1f1bde2fc8a9e022489cd200ea4c3c45791f87fbe54b955b638da65609cba688083c0b636ec51e2" },
                { "uz", "4aac616c5b757fe0b959f61142b8b687bb0ffc14ddf60b8d78eed9ce666c9c618f93b609638a133138514a4961f96ccb6b8b4c9ab5877a4cc0630d9c0253e23d" },
                { "vi", "7148860ff144ad99fe7a00141c983e1dc7da8281d7fae7289c2482ccfc9a2dee684d09934876a39652d73aac0ae9347d92fd1bc7fa030c4da8efc89c604ffb54" },
                { "xh", "9b12877b71fa34b1430b09165cc56a53843b56b36fca6c2a00ab6f9ff7172a1e07b3e56b32c49ec65a52b3d487026fac80fae15e25d01dab05c2033861960a24" },
                { "zh-CN", "1be61dcd0e70053756ec7b9adf597967c4e0f5db9504557ae513100138df28fca45c93cdb0821fa30602af658ab7eed40d13fa46a3d1392757a5ac682d4a4fe2" },
                { "zh-TW", "1170be3dac216caa84c7d68d408d3e62765016c6b222be3cb0bc80e5eb204102b58ed3bb93bb861fde1f44724277b76d1c8057594b99f91bfc71f22f978ffae6" }
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
            const string knownVersion = "140.0";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
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
        /// <returns>Returns a string array containing the checksums for 32-bit and 64-bit (in that order), if successful.
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

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
            return [];
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
