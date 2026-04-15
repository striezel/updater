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
        private const string currentVersion = "150.0b10";


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
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b7e0dbe83c2c408cf2659afd46b9d28c3e4f0d77517066370bd0eff6032cbcbf3c1d43e675d107d4251b1577881baec3dc30752b9935d7b66eb6eead7c4fda63" },
                { "af", "e49345fafa7da03e309c68c272fff0a5a42acb046b9acddacf10d26c0997f7df1fc43c3bf1bdeadeedf0ddf52841a61a6159d8876f444b6ed599a9c313fcef6c" },
                { "an", "50028a25f723532d970d1fe4f736074fd9883496d64779a3aea0c206f36cb028e707519d88d847e033bba77a16b06f93949a572d9671f0751570c0b6a4ced0e4" },
                { "ar", "419d3e7745118a88cb985252da1e172978538eab602be5de40c33621046783219f819a7640a845d956adffaa94743a1f5f9b67e10701a4607d2508c83519ce96" },
                { "ast", "f11f844156ecd08a9ee9699dc13b7f730c21ca001c0e9be2e7e06ca66b679e10bea32d2b0af5531f224c51245ce3ae7eb05ed4d076da50d1ffabe6da71ec63f8" },
                { "az", "0970a3ad1ac1aca3c034b69ea5e5fdde12d4ee8361e981f136db0e245e1823c3ec3e21f298b5a81905bd7fe212a0a073bb5987e6bc949d9d4c9ac9e48473bfeb" },
                { "be", "5c061e5582a8ef45e7f53316a4fb74441caccf67514a5dc9adc72ed8b871761817b60a264f6a055544bb3b8419a185443ea7d9ee40044c2e03ed470dd7855f9e" },
                { "bg", "527a2c716eb8f895a2dc0e690dabc5e158009d9c0bffdc6702bf1e0f8fee4a2a74953bca1ecf3dfcfea024972c05def16fbda736406aef1cd795952bc7ff46ba" },
                { "bn", "749c70c77bf8faa84146a8ca68dbcf99511729c71a690f27137c63a36195cf8ae6235e0bdd98b0cb02f5c76ed8eb8013753ede71d82c724214e542ed33559c1c" },
                { "br", "6410ed99bbff076b9111d7c0457a333c2652e2251979210f1f98166e069e96be9bb5f0735d7bd9cbc67e27ef4a28f1a6504ed5b66845a2516bbcdf5c53031f02" },
                { "bs", "9b3d152f1b172c414f6fd54cfaa48088cbce8d08031b5ad4aca826a895f66aa114e8544b2f5c14b60c44da4a3b92bf33a93c8938674fd466f4e0051e46ef02e7" },
                { "ca", "0871ad1ce4c40815760e64ad4c6515df79833f58755540eecceafb9ff5f59eb755cbed0a55c359e613249330e9a0a80a1ee62fe8a078658391b30fbd42fb0b20" },
                { "cak", "f4017d2aa215c233b6ca642a3a6c79333a201056e584ba9250e2637d218866308366c0d82c0522ff44530f53bd95f64d105ddc9943a8edb6818454b6ca4c0ecb" },
                { "cs", "6c8ea8ba4f1fbcf5194f25e91fa16e8ffd13b225beb9a74d2a71f5e2835d0ec7dd43e3262656ee0c87dce742a4c496c117056293c10593eff7c927413e82e48d" },
                { "cy", "7a671bc0e2cabc4ac1c316fb06be2f175709ca23af5efd4861ad25a5c97293292e6e02f2d6392468260861786244a97ad23117ff75cf460c8d72fcdd84bcf2a8" },
                { "da", "b6b3ee90a93bae730c282604b06b197796daeca3b323ca03f88fdff0faf083860418c79357e9204a3a436c2bc9a376564048885ba80ea6fa0523c5454243c832" },
                { "de", "2fa5260680de234ff1f681092190f730f1c8c084341155fa80f03f574e13f672a8777bfab40127330e5575903c73e0471deb56d6b737a0d0b5fe8b3f7be3745c" },
                { "dsb", "bf4c89f67961f57efad7081713082324fb5926940c76ee68f26e48520dfa471d51546f2e136acae07c4d0b5fddac5a2729d0f729e6ef02207383b146a20cce01" },
                { "el", "1e0b8e77f2c6a724aa710f6cd6638222a66b2893970a5a62a08f74e6bb96d2eb41919c56765d7f5efdca401611b28473e82340c409c44ce8c817c4c234c83986" },
                { "en-CA", "458cd6ebc7f7ae1014e87bdc221f60b7480c9038ae910cbb39ad29bff7c13279e287b861b3abe2098c3718abc19ac803c8fd54d7c624e52ed290c94f610c4d05" },
                { "en-GB", "1e2cde8deb836213d60d7e3337a69f076ae7e812ef91729e94c0f8635fa4a360a935672b21d50379ff84b559f9b9c836ae1150d03e135e8c4e28cce15baeda8c" },
                { "en-US", "10bec36374230514e980bc6417b1154f73e44ebf27a5eb869c1d1d9c208a12427bdb25afe3a918ef3b5b0731bb78656cec4d8f09d39b57cd426d8a17273dc6f2" },
                { "eo", "2d2667673d19dd254461075f61f2c54f0d01a88d863173cbe0cc2351fc4c838a39f2c09a72d89e5cd26eae319cf2aca44a176e72d2092165c4cb7d576a33d752" },
                { "es-AR", "7d550057b42e673e476e63bf63312433e16dc999d6e0fb5251a9f37c3014fb25894dcfb2085172a34fb2c04a1e9404f3ddf404f1e0f8a92f0c271690ff93ae07" },
                { "es-CL", "e4eecd1e106e0243b9dd70d44a32bbf24a13e35411e653dcd01f46059c9b461a87165d886183de64980409bcd85931f17ed3dd2b1070698634ae7240595e7199" },
                { "es-ES", "a361bc4246700ad03e6cb6c6115a8b1c6e9ee960cb1ef444dd0f695c013d03eceabb944510b545b18c9a07ffb7690edc2a302ea4a8bab1f9a6f920d621970ae7" },
                { "es-MX", "60e1bda94cb49aa1412bb6a1b4a5941052af8b0a99ea73c80785adf86c43340cb7ad613733c2d22e53016dc1cab28a0c042e802fb36e4dba919549e82cb1cfec" },
                { "et", "d65eac392e69cf9826c1466c8107d6c714342ea98508eec5309e5c3b6219d7c79d7091d86251f64d2273656531952960e7dc3e053bd521eb8631b7f8adb03881" },
                { "eu", "ef76e05ae4496ef2b31d55ed0ed652fe75f6cd6fd1a63ff045a42e4abf2b8cf9eaab81ab6cb5793739d16903ef605954d07855bd5676ffc1e127ac77d7502219" },
                { "fa", "20fe1f09733af408a48e810b47973f50e5bb428c23ee16c924666e68d9f3566f7c48524d37d1868da57e68bc11ae070abae263832d5c235a866613dc38ec960d" },
                { "ff", "f63e48a155a4c7b1bfe61848021dd4b6ddaf1d8bcea698bfa9901aa48d1f802b772f67e8b85d102caa0f998dfda613b78e854c13cbc66d36f21941ea3a7526c8" },
                { "fi", "76da0e540f4590d62742430dc5ffdf003d721228d683b0a889b039554f60140248e5c4ea57120b3bbaa62dc2e730ea5da789b8054b4bc9617c99111d8440dd8b" },
                { "fr", "802c77c781f492ad3f49163e9b46ea8dd8db89f67320c75b033da86940d01e58754cbc68479b6552b02709200642e44af4a9e9c6c0b20e2ede2d445d0267391f" },
                { "fur", "4861d4d2a2c72cd13f2bc03e1afc2e59201708e02f9d673f305b70a75e5aa41883fa2734d533e48f948755d488eedaa7ac7e8b77bd02ea9860078b6b57e2b951" },
                { "fy-NL", "bc68e18e20030245b835a28bee2d062bc8f66f82d0dccb6fb473b230a17d8b9be4bf19f00d173187446d25984b49daf992add6be61055034e5f5159cc62de157" },
                { "ga-IE", "b519be2a02676aadd029aa462ca22a4ef829797fc1c78543783362d1de75ca002de4edf032c1fde84b9dcad84305455f2e8e74ca42be18a5b3ab6d4302781142" },
                { "gd", "05dc668378256a43c7e245ed95c85cce27fe06e944d5f06ee72bda1105842a86cd143599c852200c570bba04044d842016e2d070ba2203220bf236d31af9c334" },
                { "gl", "a6e0a913dae870fcd1c1a3bad487a65d1c15b1de516330963e2a0bf95c349035afd78de60ce8a489afa98133342cd1f8c71e3873110f31be7375544426e601b5" },
                { "gn", "64f531abd2211f6350fce28fe5d0bfed58fd97ed6ff6212a2cc4e0d7e2b6c66ad1ff77a80ca9d6f665bf3f80c03a7f217debd7fb2b527a6acf6916a064301eb7" },
                { "gu-IN", "4274e7fef929d3938f2b47988f41d19494ff8a9dc19fb2666f1b9cc140fe39ea5bd43f261a84900ca5063980a8ef93b156cbeec7725e7bd44a7e96e4fe6da03e" },
                { "he", "2f0082c4a0e12b6146173457bc2df1bc12b21d85b2090b6104587ec7169b5411bedf82db15eb958fbfe4e7125022ec3e3db76cb80fb51d88a0c6392977d3309d" },
                { "hi-IN", "19182c14c382012ac47369fc0d50bffa4442c305a751ea8f4de739df14e82835f6c75be16cf802000dcda61630af20a9ff1845ceff89a58595f78103caf092fe" },
                { "hr", "5728bfc1fa6f22bb818eeef44bfc9fcccecd3874cce616b2badcb18abeae7c29b6c91ef03f732ef15b297ca61657b8a0f3280d04606a17bbd2186fc8be4ea2d4" },
                { "hsb", "f42e5ef0c04f175343cbe84af0b845065b900a5893178ff29438ec4493d575dda0631e193d5d9265e18c6fb9ea116ccbbba18142b6cd233cc276bf1d267a9110" },
                { "hu", "1ec75d8cc58dea10e9b7cb8cc7b46527194cf784179e0055017e9ab615afa198b7d910ee1af399f9523f1186924fbb0b038218505b1c22fb3befa37f58639c89" },
                { "hy-AM", "7b6b41acef4002a0d2d055d7c61e7b5a17ecf10f67c09e3be74886cf190b1035e6dcd11103089f900434a31230ddc0ca8aad25415a64001ff1e42c6ac41e1024" },
                { "ia", "74c690f52b028ca32baf76bce282ebcd7daf5bae0fbef19898111ad00a19f4b3e3afa2a8b5a7e6a1148158eb3a927601d65e1f5b8b26c7f42820967b953d6971" },
                { "id", "b5966c26cd7db481a911b60775e9412278ad7b734224eaf0efeaa92d9b178171b8596c8aff74771b500c30a1d02df76d445231ec1526fefcbc312933b74e9379" },
                { "is", "d1de216532151f692aeb48f098d75659c5ce4f9cf4166f8f549893a4a244453d89d28ea2159fc1f65310824a27bb0b4501aaaab9f40378e1098f8e09800786d0" },
                { "it", "187804a593b6b7929eea225c2e414948ec4a7255c83498b976233c251205d10ff8f7d482a9487456ddf931d10cf8d3011eb0111d234427d864cf07ed14c0e24f" },
                { "ja", "2193f3920283d79de7bcdaa1873c5ec62765715c64f684b124f4b6fb4df1c81965d2c39c729ee5c2fc4f37eae2203dc23d63370b23d72962c6734d10970b81fe" },
                { "ka", "cc1c70905e6c06f1a7a04ca9faa9f83e639c5237bd45e980f1a11005b83d33bc6d9a9a7aa5c8c3166e22133aa931c075d2503e2abd83250d2c10b53e048813db" },
                { "kab", "c07de5a64cf3591e4be46e1e658d204b2d1e16fd7eceee0b6baef62472cc75ec8e5746e2fd91f1f7f671a397d6e6947de5e217c4cbae9dca91019ead5c660afa" },
                { "kk", "76913054751ba9d45bf523650879e1efe3c9a6c044b2c5547ebc26eab9bd277a4b3aa3719a9b91c287b6d11de0fc34ae20cae6a21dd00b4de306e2a765b37d79" },
                { "km", "ae42ed883441024f781eeb2d051be9297d4c957d793f6ccf6714fdc09b88c61e78ca82331bd3e51468b626c4a8c866988218047d5573ff2b455192923aecf503" },
                { "kn", "3c602ee2b52a66dfe5d08feb9bca8b1385bb38830841872ada075493eb608c8248f130242f77fffafc0ef1646c138d852815af13214ca9554df8948a93981152" },
                { "ko", "60b99b2fdbd074c8e12c4617d7104ee617bef65a04926b94317c18569c8e16b8f4954c5e225523ae1b0d5f36e9ce22b89908a317d6b355f60bda5e83208502e7" },
                { "lij", "a29e62c5e46e8898fcdf28c6196f0b45173f8e9d461dee809aee51bbfc5300e6224bfb17955b194fb02ed3e7131e7f5cfd8d97942ebfbd3116d53f32ed087995" },
                { "lt", "bd47e10fd68873f97fd5dde644438148337fb46b44ec4325bd9b2236c2fdfbe0314a1a394d22334a8df612714bfe26080fe165f3dd694a859927f7520321afb3" },
                { "lv", "57f8fb246cfa9ccf8f83eea938d8a69958ddfcadad5bc8b865dcec8a5bb3b92a018e2d6af12bde37ac957dc76d9508169318d907bbe33d2c4e22368d175a5acd" },
                { "mk", "06e825eefd7daf61453ac5eb1412aceab7dd404bc9176a36a6c5d7baf04ea6deac445ae78c21ef7c4fc6da1c532f567e78d6a71da7caa8a203eb14a7b69b2a64" },
                { "mr", "b97ab983df603794cef9d22aa1c9eb9657987a6bfeaa1dfd4b0971aa54f97bcedeed552f37813d399523a72a63f61b2ef547da73257025fa862d168f33b09df7" },
                { "ms", "7692b757e9034ba6ad5f60dfe592727e72a075eb114ae81da24e879ae2d8fe08f2ddde2a78717ae2074a4c13cb3f1b646f5d1482bd2a39c5f34b3d16fcb49a1b" },
                { "my", "4b28c629403896dc545630ca118de559a42a3f1711e72488417b4f134c39688316c53f5cda067f4ee305cdf3d7da864b3f73e367682644a503c31b0a25f951b7" },
                { "nb-NO", "1347831a0ed1d275d488be26cd97804d27e50757a43c1ae4f9ecee1e9edb460524c94c5235829e2a07c5cf89341d9bbead3cc77d23bc59dec418f70080fb98b1" },
                { "ne-NP", "2c39ba2952f763820e2535d4889d5f5b2e0ea70ce347e99317b71431184e6155e3e3fd58f83ed12379c49fc9850d6b43125fcfe548df26582eb7f19c7b9390c3" },
                { "nl", "21c875f101c7c2660783c15a190b57641019c3f7d53083e905011587bf3a50fae81859d9034d5f4e8bc61d16618d6a6539e3d80ba1c14dc1c415d3e9aa3b7200" },
                { "nn-NO", "5e45e5a99f2f663a5b76121eacee7c475ce615c4afde34dcc21b011bf2440165157a450f1397b5b435f6c19d4583a723b66329959e0ec15e50928f521bbbaf3e" },
                { "oc", "63a9811291cc2a5d40d8e5f904021d90fb38778394eddc793b76d68159bd7249e8c927fbf18435ee309c68d2d49fd68ddba64b35bd8050ab92bc865cb8cb7cf2" },
                { "pa-IN", "6cdf3625017d96a17629a2ae55930c0455d21693f2524326bc472d6f8e2bc9776b917db69b83a37457b4bcad3fe17502874f96e2b297d715053af1aaadc8431d" },
                { "pl", "c276c079df11e93054f820f60e0620b8e719664e3207680e38757152a45a52647db0945e2dc75fadf033a4303b8d0871729e27c5156cb76f787941a265e60c65" },
                { "pt-BR", "7a2c2a2b9b484805c77cec3994b2563e3b8ae58ea8d71ea15e7505d82adc0beba7cdab0d42d5c49b29428e1b7919232b8e7a539ae7e0dbf887894685b742025c" },
                { "pt-PT", "01388e5bc5873abe4652c8a4c9d4592306fe7fd511c3bf60a81f847b6ee013a9b4b13c4fd48b65885a3786be762d281dd15cf9e51c4b9b81540c3e28e120ed30" },
                { "rm", "9d2dcef84f78b9f476b4a28e7b9308c93d319abd609814e582fa6910dd11cf07cb93e4cd54d46e8631485143d66f69d7c530692f91d902990ed11a77748fb599" },
                { "ro", "7f02fa76839ea6a7e11c6544835c8aa9caf1e302eb14cbec20ae24ce19dee1e201ded79996407e7b58861b07488b91c35ef5d53f19a0e129a71d3259e8ad46cb" },
                { "ru", "f62a900d8a570b8420858a26c68624ffbd8b8be357563cdf30e274cff5528e522b900155c8eee646a8f1d5fa59c3b0e71b78debec8e0cfac4baed8bac1f4749c" },
                { "sat", "c5496c0dd65d0be728bf41127e0e6e6983e30d5f15451029bda8ad9e7dde503517c69a626b0b7a98c8c3716be14eb112c5f5bc33f579d89a8222ebf0e90e5290" },
                { "sc", "510f8e2f48abcc2d9afadc25da4e63011a62fb144142b50af773226a8193dcff2aab6d14bac146ad25fb72b25d7b1b6af5429f47338936d3d28e4d8e5ed8a79d" },
                { "sco", "e349d6ca6fe956dc6f2e245396c55806ba7263dacd910e15fdeb19b7af3a692f030b728cfa1e9a5c0a5ff57274d81d346a0c5d6ce924dd4cf9fbe0abe8d0680e" },
                { "si", "56aed3a3a8b7013b9fab119222414c84d42638d7d55b9f8e27ad70b93187869c5aba3185b8ae6fba0afef37863bb61db21ea80bd14a43337bcd692e1a9ab7799" },
                { "sk", "f0ff574e23c17a4682b47f3ba0961914594720a2ffac2eac667fa63f8d20b670d58c2e837dedf33880a99d6cdde389102367fd47ce782873489ecf139e405586" },
                { "skr", "db96fc1a73507b07adc40ce72cd67255f9d0cfb9245a3afebbc9287bfec2a59f11ecee7b151438d8e022cc4b4d54d43a1cff7c7cf9190bfabd9a6b7d67474515" },
                { "sl", "3d65fa44ec374cbf77f44ca7195492a9e79a3175e33b7ec10bcbb426d0c83ceee6b04fc650a750cd318d397125c899a17e8efd49c0748aecf511aca84f2940e7" },
                { "son", "88cc6149f52757e24d012b02e51ce79c151c29d73b5b5c9300026a80c25b274aa7467ed27aa2f6a2ee0014565d7717a4b09b5ac0cef19b1e9e3238c8440b5ed5" },
                { "sq", "10b417e93e8afdee511b2422eea74780509df7e4a40c6e7b7b9481ddfa584f31dda8979091e95454330fa5bad20841cfc76f0ee7612904334c5d6a6437f4dd48" },
                { "sr", "fb9c3451b1a571f35353d3a10b1963b61b44c57f7f2322d0037773f183779bbb1907ce138e0ac08f6d319e0d085be8a76206b9c7dfa635ddd02b42ae0a0d541c" },
                { "sv-SE", "facfb0d39941c8a90f3e94b60b3cddc2247ae101f817d80813c9dfb503578c1d6659d282cdd7779dba310e9d1919288bc066b9ec530a28aa313706954bb5049b" },
                { "szl", "2dccac1cfe6cce1283ee088306a16408897835b25361156ebdda9da1902541fad5ab64504a3fe3b655b83933d25bfa04565fa2bf5cb9eba3c779c1854a0e2f2a" },
                { "ta", "97675edf8cf1e57f6a8cf8569dc636fa3339485c9366760560a1590940068fe50e637c3aad736c1a302d42b7994badba18501f46d124677e41e4616dae1786bb" },
                { "te", "83c357a1ed0edaaceaa09d201236748be11d6ac87a31d77bfb1d9b314a217f7be27147366707745290ce400eb1e6d5835d711bdc179c7ef39c98f2279ac6fdcc" },
                { "tg", "9f6746bda65edde8b91d1f289fa3bd9fdcf03d23ecf869e430675310d9ba4a5350c38d9846570a2b44fe195e2ef945e9f4e86a239d72d1b23e5419733ab11f0e" },
                { "th", "1c88f59c4dee6a2c424811f2df04c480f522282268d31cf4cd172f834ce109ba617ff41572656d571e4043829b8ab4f23d8f7e6b731d03c8b5c5092394d58a23" },
                { "tl", "564bbf7996cda9c82b5013167ae3e4868c3de7677c2677b0b270611fc589d0a68dba30cc289776be0705a710394ade8bd45655968d44e7bd807098257c53cc51" },
                { "tr", "9df125c062ae0256166b45107c9726e4a37fe2b24b502fa5cd71ef3bd667dce73c367cc22f3241f81f357e272f36367cfafe8b831c5301c2d0aee61622d486b5" },
                { "trs", "b53c7ff44677fa7c3cdb45e7cec8eee1af5347ec49270034c66af5d2ed005ec8371e3d8086ae3572f921b653b497fa799db8aeb33c3b935c2e798380f6997332" },
                { "uk", "c956cb44be63bdb176a043c622a911ed9569ce16431cfe0546cb2208997f647f3807cd7fbc1eac861c3fbc433c50ab94feb16d0e6d3da6bea16adb37cbb243b8" },
                { "ur", "003f47684e208c841533681da8e432312b69e581f6cb6e5472317be2b47276a92b930bf454c4372777955e60f7ed2cb124ee6491bf5fa918d45436c8df9102c8" },
                { "uz", "82da8ada5127f5ed07ce0f1810b575098056a57a0abefdee2c1d3f184bf0b6fc190214606041a044a336f9b3fbd523831662cee86436a7f8f100fa35dcf453d9" },
                { "vi", "49ffdcd8ba507052185fcffd3b6efca829783bb4da071817a27ea4a3eeb63d02be67affe04e5746c8bf7a80ae0d7bd392733bf34dd125d0e5e444de1744921e5" },
                { "xh", "88f36e313cb22afd4f52da178bb27a48790fb0f24c3fa76876895dbe1f48a967f91f25b7a414b91836d7fedb17f6e005ceab71db8800dc4f9ec35d6dff95f7f7" },
                { "zh-CN", "3d347c2e6ed6f655650caddd279788959692481e14187f74f43e9da0e44a5ec5238e9a4425b4762e23a5665ac5a157277787b16f0130e591d3c0d801fd8bdfd5" },
                { "zh-TW", "2302ff037dee6335ff216e2979a56a7c4a86234511d1074e8ebaf77691ea4460b678a58d54c3dc4c6dff6c28ac67d7ee6915b987dfc6b45bacd43c9f61cdd49d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/150.0b10/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "be2efb125c32d11936f3029be3317a88e2d7bf4b854a5b64907c6297876af848220804b9b1afeb75a517c6a79fe4c3bf07b602488b3bb62873abd38a65f152e4" },
                { "af", "ddb86905bbdb9f6fb00f3a2e59f397577dcff47092eb1207cc700aa5385ef3c3072d0947a7335057a3283f82d7e8f680ebe5dae8e317ab20daade5159d432f25" },
                { "an", "80c92d2c3ffc43eace4d87870afe1e5e0a4a8ee3e974e8faea0a48a2035e24d6b6e9df48d41cad4162d609d9a2e00f6fa44ed8ad5d66e452cf93c44915b065a0" },
                { "ar", "f50a68df89b4280d5a7059162850e141ff2a1d26fab78f7152da922f15c72617bd27de7616f286297a5ca31177fc211f016984bf41a60879a82d66ff381a4dc9" },
                { "ast", "a3911c1911e85e563f07389b3acce870cc238b71171c7bfb0caa8ba1b9185428bab4c17af4af305fa70320d8f9baca802b24b8348e859619d727a27949fd8e08" },
                { "az", "7c35757de107c414a318910cda3f63a60b2c71bf66c4797137b58f45dbbd9588f5a3daa817c4ce03c11df02e78a3c83b07d9f466e1f41d94d29dee1db7508104" },
                { "be", "d6f1f1a29c9ccf4faa7d1946be8eecee1e2f75f04db7417d97fb03c59b2971c1200286523a5495dca57e5ec224398643805dd4b651047c138877945d7d837567" },
                { "bg", "9fc6d99800f140b74e8af8cccd576e8ed5dac0531b38c6ccafd37d2a2bb7733afe95b17052819975bdc01947ee8ac13a5542fe42c1bd9432a5b719a270d2fef5" },
                { "bn", "7b415798fdf4f1b8da349417a81198ad2d13beba5f23341387d4da4eb82400bac6a03a6dc00666330667a7e009b0fba798d46bf1055f71a730cfbd16bce0f199" },
                { "br", "6697a94911e0b3689b96aa01d2659f4d6ad74e6375f88d368c401adf9d42a76a99504de927c3e39b998dda2c5dd4c9278edaabffd02cb9245f305748916d1993" },
                { "bs", "d34b703b468f65d57f40a2529f3ea56ab33d476c465d2757f8365047451948d92bca3c79eab2a115ce3e9b1d51683546ace8d9cf18fced7ade54f4e76edcc363" },
                { "ca", "75513d473640d4646dc3cc37b4a423cf9c8dea27770f81ea0ae7781b9192978cbee458bbb8159e144882742cc10a76d66059c9581bd6e0ed760aec1ff95f7822" },
                { "cak", "869032417993724dfa841602ad51d1c3e9a3742cafe09aac9b2a7f17c9b36a31807bc5866f1d674aff92562168e611a7297b46ec38a628a1614d6d0e63126825" },
                { "cs", "b5ef2c3a76830f361af5064e4bd5e864965d84cf2a25fe77180f7094baa26e56a4ff4a0279f8ca6a01772deaf52e82291f836ff459828ba121e074c22b4d5652" },
                { "cy", "f231f1914fec5858920d96b3e44659dc695b9180dfb3e3ab620e1f73f37b3b2ad6d71b070d55d818ffa9e7e9e1f01ec2a56415fa3e41fd957e91de4b8664b366" },
                { "da", "d92b4275c107350dc75d182791a1fb98e838a08e4e90bf3d86ed5926dc9d5ebe79645461b6e12feeb2662151687205596c4a23c2c6db019a3c967c6c213ee7eb" },
                { "de", "a93739214bd1bcf5e7ef3fb25e1ea4cb395f73ab640434b3674c0e5c634f4832964d544805eb81664f66866bcf3128f2815b0bd9ea4e820ba1a35982d0ce0c97" },
                { "dsb", "cdf28ad6a529e393e4fbb4d91b2aa0bd941884506a4c78bda871294480e5d0b5bd5067ec3510b6cc37cdf1778632dcbab3a8cd669bd5067cbfde635ec3910aa7" },
                { "el", "85ba99b92823f5202b776a496a635f1e97e9fcf863b665d6dabebb4692759f848031e5c4dd4850e3f99d4befd20b62bea2b10a2a1c305b4ab6c69aba1b45b2bc" },
                { "en-CA", "b1d3edec829ef52e80d2cc582ab2c994319b40d8745e14001e66b2a3d544c6c5809cdb5f60e2529d7d1601952a43616ccd31880450f331b5da49b63014cc5460" },
                { "en-GB", "e3aa6753f810ec2b35c60aebb4794b9228549fca802d9cc3acba620adee5dfd7d913e7efa2e2ff11b14ebb7c0c16fce0699eee872972f823145966317e6c3639" },
                { "en-US", "6a2fca6887a87f1730af204bccb648f0bd2dc8d90000b95a8d2bdd904e87ac8bb0597851909c3aba8f7448f6108a593568030b185c689c23b8ed75dd92e56c7c" },
                { "eo", "4ba508f32e73b0615f61a0c6da5abe647aa26ac6d4b6203f3dd8fde1e88ac86bdfb007a95b391af31be36f46861b5034a75ff315d3c3bbc6cfb48f259959bdbe" },
                { "es-AR", "fa0bc2bb7bf80b47975ad0c6454bf026a9db40c9aefa8597a69f6ddc56bdd10c44014cb456e9e5bfb1353e0b0bb807b3c0f4ddbbfbee0e93cbcc41842ddc8fa0" },
                { "es-CL", "c420201b3ef97364d443ade0cd65b84023a992a730041adf96bd1941c77aab31bf8ac279004f5afa9db43f92c34a8d1f5953e1411a86ac1be0bc830ad97b6433" },
                { "es-ES", "d7cc99fa66fd7061ab1daf8dfb0305826fb0cad0338892b5ddecfc51fee88c5fd9ab025bbf8c5c6f9e584e87a14ac92529d39db9346028b41275312aaec957c4" },
                { "es-MX", "4cc4f2d189fda7acd2784f829d9d7548eea119ed1d6215ed65380d45e93f5d4ec1547b86124885857c0e7c4bee821ea9d397f627e9694da3fce136ff43063412" },
                { "et", "48ba0d53d8c4e3ce885981c928ccf99156d8843dc8e4a249bb108efc1dda274911ab8ca0b69e1799a3ab45ed437e4b013661a0f3eb7893e23620a0b9833cfe1b" },
                { "eu", "9d194a3e19b3f36f4813e83f25a978d390824ed72d293a330b4c76cd3942381c614ea7c6c07bfe6d27245a8e172e04b40793e3f5c836951ec46f6f2aea95f0c6" },
                { "fa", "ca7f0e67ca773bd1e4a5bbb0473cc4e343048daa2c7488b6e4678c980dfe3f953b5b50933095ca4fa4a4bcfc51f2e854a729dc9b583a597f4a5142364f8a0518" },
                { "ff", "7af09d71d177b66708abc06ec1db99eb75dc9260b4c323eef7eaff905e538df63aac9f0daf1e5249c454c209e635f97ae8973d1f4499b21ba20214528c2cb38c" },
                { "fi", "d9ea37a6fedaded80a4b2fd52a4082c848d0f078ead05ed8db722db1a3300bc71cb12f3e38232fdc91c9e2438e45ab5da6f89ac5f1fbf557936855dc709cc6e8" },
                { "fr", "d547ed579d6bdbbb4501026e16cd2e04af60550e20b52dd3104e010af7524676c596185ac2a70cc634f182a9fcd256d096e89a4b73cbfac476d9a2b8d0842b9b" },
                { "fur", "a4f8f98dedd31d4e4ffb9532d3d90f24cbf01614792f1fba3194483ee0c994f172637e34bd89c1fd39a1415bc3c1745fbdc7fa94e87f6855db9f99e03ed0c818" },
                { "fy-NL", "b07e6e9316bf665ed3d9a4ed80b2d49f5332caae555ca5007faf4d180b9b48882f127e317d2e479186679551c94a77480489f6e126a3e3c7aa792b817a55d87a" },
                { "ga-IE", "f5736b3331680b2c69c593a3c239e835bfdc0dfa3d064ee5feae3a987afb357c0bd931cebe5d03545deafb957ca5e8d6d9aca083f1540bbc0f9b53fbce14b828" },
                { "gd", "3ec5d7ecfc28978e2de188aefcc62bb0b04dfaf1eb264ba3662149f21d74aedc6a991fd82fe4bd9f90b40d3ce137b7f0d23188c6318c9fd11c7b5bd7d7dd3d55" },
                { "gl", "ac402d3e92f3af797c526ab4170af5aeed15b756d526a0670424e00a7d6b9dd9017efda141e1e3663abac9c7c1957a52a5b24ffdfbdaaf0938ff425122025b99" },
                { "gn", "5d29f5a464bf4ee03b5daf2a771ba1046699019d0cf4b7c6c9ebe2120848c799c69734b6acabb87ea6655d35f6dabcf653e401bac861d3450908fa1719e12791" },
                { "gu-IN", "59d058d6857e41345063f878b92aadf0248f4b4cd294607b474604c50bad6c9381976d0176d4ad2812ebbf13d5f10159dda083f793a0b0bb9a0a9642ab580ccd" },
                { "he", "ec142a19218c268e3b880059ea395d34e575eb3d1540d20b8884c19ab4366b3e30065de29500e419c4112f1e38832cf7fcc98804096e1c71355e3fc08a13fdd1" },
                { "hi-IN", "8a4114e644b8f8db6582e37c356b573cb0cd7ff77d63209e5585f19d477a7dbdf71c0511dd2a921b8ebd1a61c17fdbb25d2ca6a67a816e815aa673ed7f8f8279" },
                { "hr", "29b59dfbaa9c03dccfd281bc35b22c457461cd89880f7c0809c69c452ad690c79e1c77e923fbd2a16a237411b77623ceab8812a9895b02f3f7c3d4b2b549dfa5" },
                { "hsb", "3a594b28db7d10b3acab10ce2e8f18016d5c04341246ef589fa734fa218903a7fa9702c8c0a6baf0e60bc370c5eed725ec998806e0f01fe0cfdaced3c95025b2" },
                { "hu", "24d100fe6d09af7552b115fced1a183f18136f9f9b8f4378bd5da3846aab1b47c0d30cedc457c8a6d36813ae6e19c1b8d7e1d6340e208b252006a07d35e6bace" },
                { "hy-AM", "e869768d0214967f931d4ee189ce17caf14538eb612e85b8364ae00ab2b0447ff927ec76f01703dbde60f5b0cb98c60bdf9124e0fdf4c74fca7ec9bdf6854b44" },
                { "ia", "6bfea6fafea6174e665ad59005e63bdb0f74d855b706f96c96b099c9fdf6df6daa72c33d46d4551cf552b6f8b6185053e746d54504cff9d2c5ae410e8b57d935" },
                { "id", "b5e665fb6f4a6f8ab80d117f79018ebf0f62fac0f44147f888136d14246805ea4624894741142f5b1bdc274eb6ec5931fddee0eeb03345c8cd80897f358a0f95" },
                { "is", "fd82907c706da5d859cf49c96089ffe5939c2ca8562dc884477df124540ae9af766dc9afe0d96361943c1685282b1be15fdcd86c661d05a21177acb5ac714ccc" },
                { "it", "bbb56e32e39017ff8a7899566e3ef0928b829d4d2ecc695cd670c928d8434184bed8840bdbed9b7278895b6c5dd01bf4d83dcf091a437dee1f41e070c582f3e4" },
                { "ja", "ce8ef5f76ff648527d85781ec528ead33d313b11a7dc1ed07c2ea98916272970e770cbaf598f819342d6cb1dff6a75c555eeee2ce8cfad5db010c304c77e18fb" },
                { "ka", "4ce73532d67f4561afdc34114c51b2c735e1518f17262d8d6bc751af4c55c3345d9520c6b027627832a86bf27d260aa7aaba1e1f6ce32054bc145eca088d6db0" },
                { "kab", "4377737d998c02893deca898b9b5e0f0cd6e1b4eec25c1c48c3383e549a9924b8fa1a4ad14973d63130e63de48ecb6ef0042cdb309677aec8341832c01a8a899" },
                { "kk", "71a4f6ec0df00df927263de124dbfc2a240eb613c8637d9afb01777628730b2649682215b4919cf30164ee885103233521d9bf0b3ab831f3a594505221e8edae" },
                { "km", "0af8937153f2afd2d8e2e5710814cbbe07583813f0a32409bf0d3c1029a2d96b5840ee6cb0aa251f04691df329a3bf2e7e60fff7f82017cca3a02efe9d0627ea" },
                { "kn", "ee861790c141196426c7b59133f9ada2d9d74e7c51eb62b59b273781e14446ad452fab06fe9fde05389df63c936bfcd3b85e18a9c69468229d1cf256f7678779" },
                { "ko", "fcfd72b8afc107fe0e5ec57b79674c52971a799dcbc4b60d2641c94ba80ea326533d7917508915b9f31fbc99672b0fdf01375e5388891fe71082f248635e2b2e" },
                { "lij", "6021de3eb1dd961c68a1ae0b7ab71f3ad0cb6024bbc5a5873dbf55c4e6f4f3eb65cdf8705aa733c4cdf3748834efb534d9f620cc71c5ed734aef85df76a1c66e" },
                { "lt", "bd3c1cfe2f9203c47ff82bc3ed6ebb1bd576ef87297bd73585c2aab532c41b9f76f6befc0bf2b8726c7765c15b8eb4c7335b4957f50c39a98a8c65b3028b7ffe" },
                { "lv", "ac71b8feb7bb13c0b470f26dd9d92a50b954f35d214a5010182f87ef30568e0920d65ea190ac73ac56ee9beb31a4d39309e51fe45194477113979f6b2fb43a4f" },
                { "mk", "44d9266e24cedc6f0a94c2d492aca4830fb2de6d7978eed1d097d247ebd06a86ea54fb5b02217b8f2779e0fdbf4590605068b22c2e86c4c25bd66b0d95bd0920" },
                { "mr", "6f51d31293215c64ae2ec9a081eca3e903b2db597ce578a416d3284c15ca55054380e5ae88a8d9ae82f3fce10e0cd50db6f0f0ce3c129a53668021aaa2fc84f4" },
                { "ms", "bf3ec07f9c7b236b01c4c8b3919f399a693911cafea95d1865df5bbfa98da1c083e37d2c0fc262bbe5f5e2d2a9c9c2d32c5880acc82fe4a52afc79b9e38a0e4b" },
                { "my", "8f5602aa614fa8385a6313c88e96388159dfa53b6a2b00350254b4e15fb5e2604411e7cd23b189aef7b798248bc45e3cfc4f4c06e5d576a0ebfb2aed30cdcc92" },
                { "nb-NO", "e72bf96db1bb3b3637972aee0e97cc4ab5d9c9da740949fe961e8e5af241851020ac73cf8f7762b0c00316ecd4308ecaa57dfa4be39d0721231a21c0bd0e2fdc" },
                { "ne-NP", "04d65d4f136f13fa260af001e558c2577e768e2aa9349383d263e32fe172cfbfd249bed71ceb3e25b5e97581957be2042547d57a9b281ae1a4f1214facbdcf80" },
                { "nl", "29d93c6d3eb6d86fcc37177c1358202e062404feaf8954636a67d64de495793266f221a13344774a08e765b32489111637a0a8af06ba723b6ddd80575fb8a021" },
                { "nn-NO", "4c4335245f173aaf5e5b3f7979477611de8ff6bccbed6bea1acc5f5e333f2b5378ae7394bf88e0cd3a4dce59c596d0f4cac6f71ea26683f256847b8ed036baf8" },
                { "oc", "870ab557a1546d1417600fc1a9d572c3168ce12c1cdb9175442eb8ae40d16935ebd6212a98a2bad10476a9b58bf28c490d4123538996654acd6a3eebdd7fd825" },
                { "pa-IN", "c98dcfb181f59e77e5e7b76f965f0d10e97e01de55bd8bcb9fb8fb23c9a97aa497a785b9cfd712b201baea6e0ea6e1bbeaf80171684ca60f73efc6c8aeecfd5d" },
                { "pl", "7d7832fa56ff27de54966554fb442a81010cb47883053f14c82a355726da388014e75de86e511d364a845c05091871854a0dbe78a6c3aed96b0284373036db0b" },
                { "pt-BR", "e236b77c098c31ae3886a49b07fd2bafcf277710c00c8f3e42f97e9cc8b471c8bc10dc3c6996397c2b8815e042cc461d50b3eb81a6b2c627ed5a39a819279ac6" },
                { "pt-PT", "bb935fe8b58a5ca8892fe27c43e40339f6e42f8d513cb6a8b6532ed22e414b94193d645ab10c4698c0ca241e687eb9ba03302f1794a889ac72506ac2956b12fd" },
                { "rm", "4e0e445cbcd8b849b816d8040b58381b5cea04046615512cb88d5f8a4230e9dab736ef24262df983a5dc8845cef40745916746f6ed6facbb14c107b5eaf1f83a" },
                { "ro", "809d5744f660fc7a1647f2bdaf2b75781839a02655c291739256254f025e41e38b631c872adfd3c4612b152a169b77c278b074ffc6aea850d8e48e042f4a8aa0" },
                { "ru", "6b2980f428276b2d5cda72902394c681155290fd589eda0ef4609ad97f183600faee17f9eaa9d84c1caa8b86d5236aeb3a727532d39f70acbd18e6542f5319ff" },
                { "sat", "419ec41961b6a1b4b2e2efd88d69e240a75264d0473c5e94b13078c62740df6c288e5baa0918364f07e211e5bcb3462d52c23711d8d1fda72424b506223180c2" },
                { "sc", "89d50fe8b9043bea4bc1e6361ca75d146b2e5c8d2efdaf278e00b7a3d6971378ccfef149fd9e1bcc283ebbb4267dd1b94474a58f64eb43f8349b5a982d9d28d5" },
                { "sco", "c2c368831d4b83b3f969b1c6043e14d8328c65712ba41c3dd0773d0e18df76e387c25c9135c167b245ee47bb0408a36152137ab8a59ffead9167c7a3052ead97" },
                { "si", "83e5617fe78740b9ac7a7af7ff78aa7c5b28a0338ddeba7b4e891e86673c0576e6a8118f521b43fedffb214b58c9fdf010082adec99c494faff80673273d2ada" },
                { "sk", "22fa50c486b18584b8250dc01d994723884b731e825041c31c8e48fb162459fd807d313035ef25a1d9715636a1da4768300b68ed47a04ce18a48362598e35063" },
                { "skr", "592b0e31108abd57055f803bd58f837fa6907b9821167433de199d5db291056f95c97bca15f836427a69abd30650710b8953414b3bd84a6b5e3aae4d4146b0c4" },
                { "sl", "4fbe9d1635b127ae4ad63e38cf08090e9d2272946573654328ec674ad5f2864cd27cf47cb54edec896060956c08aeccfc1989f1f61f6e97de937c7e1862cab5e" },
                { "son", "b21a9977312d3904b93c6bef216d9cf3547d159107fea009448deab21e0620a4a9cd96a3c80a516fbd8e60abb886c0c4725117519df9af6f4ab93aa8142e224f" },
                { "sq", "d03d10dfcafafcd6b3e8cafce2f7e7bd1f9300337d8fb102aa21d8937ef91d0c6a6d2a08cfb2cca22c8c3fac0fb31421d9521bbf4ff81aba29e5eca84202653e" },
                { "sr", "89d3d5f0d9f12e322814925b6178c1e54f58a66f60a6bef03e00acd2e8f0f2284e04bad70487042b30d9edb9d156764819bf4c8de8a5267e3de0a9313bbdeba5" },
                { "sv-SE", "9997074669c9abb66d9803ceab9d95b138ab3f8757b03831340d64f5a4441aa755f8a81a8210e0c0cb34f6221a23331fd884eb4e86a96229d42bce678e6c5219" },
                { "szl", "804051a01cec0c65a324587af9312f426e6ef43c28b9a2c8b23c61d5a94ed6b5c53873ea517928640919dcbb20c8a913f550b1568f08dceea5b3acac2c9564a5" },
                { "ta", "52c4e22aea4e563d9316b560a1f0386ac3c8801bf09e9872a5241ba94119a300041176f0776cb2d7e5653c136e4391d39df19af71c2a3dd7519443c3077593d2" },
                { "te", "b9a72a03b963b277f3ed0dea6f756235928d466e397c4b7e38a804284adc6073502154844e448cc52021dcc50c6ba5b372acdeb67777649d2f17d3e7c0010e67" },
                { "tg", "a610c01ae3973409dbaa5ef207fefb5009a7ef139397df92773cb743daafef42b34e095ca9b37ee80f19e6f99c10c356786d34d8ea0da6a602edbf07f82d3e59" },
                { "th", "41b501f7a6b1ae2926934a985f1ca4057752f29cb779ad45413639ddb736ef285e42ab23f3da35c5fb55282cb86b3322f94bb3d63f46e393ca922abd625b8508" },
                { "tl", "10ba2dffb1641ec9ea8da7299de32666369dbda9be41fb67056ddfe07f1ac7df3d99a7e4f5ac4577f1b9ed6c49043cf5ac3f108c1ef54a0eaede1eb1e08e0ce2" },
                { "tr", "c5a7c26858895078960cfc5e41bc6e88fac0db31c10803f8c910c4dfa4561d00f3928f5379179d12c33e67c80a9f39ef3342b5ce05b98fd396fe91fdd99a5b5e" },
                { "trs", "133a8070dfbaadc42273274f519b9be10e0aca78ae9489d5403766f83875f4bea5983bff97d4193fad808b63ef665f667a5baee88f6ad1b8282ae0453bdb2baf" },
                { "uk", "aa33f27f47ec96d7b4838ba8123636e1b292a123628c3819d84a8cb3b061ac6af486f99c38bd10482ba4cc3434f5f7b61084d092b21d2ca005b515d912202914" },
                { "ur", "6af8bea8e5b5f81cb7b5c14f2be281d6b9c868644557612c84bf788e85408ca37dfdd05f62963d293395fd84fb9cdbf2a25e0e215e86ab57f84640e4fa7fde51" },
                { "uz", "61e8852774c8c08885022551453cc44fe0e9277e07240fffb0ed0edb6f07b9bf78943c7939ecb0e83a8f93ad0c819422ed60c7164bd39b78f9dcafe51847c31f" },
                { "vi", "6ac2463bbbaa769f228499d76540b62ad864dede9d39cf5d60e7787f8ddb545aa57f3f47f89a5a9791aab22e88b3370108ddd8f3c97a02ce17c09f08a255a607" },
                { "xh", "6f1a1134790cce0a694eaea492bad7b82f1214e97eca54b5c018f48b033ebdd0c3e2b78359d472369af3d747ccc70e1140d08b2225ab4720590e650dd076f4f6" },
                { "zh-CN", "eec8b94452d4ac502fd7a7f4c95d729d15c218ae42fb7e99bb27277f67c15ebdb7d1b1145baa4469b14015b54d2e61c8c1828fcd1e372de54ff7c32aeb13b865" },
                { "zh-TW", "cb04557e49363614618bd93ae4fc1d8ebd6db3189cc2da6a70d7b36ff1508553ce53fd09779ee4551f1542486e252dc8cbfc1fb60e9511ea92c9c31416a3b4ef" }
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
