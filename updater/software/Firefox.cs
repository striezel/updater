/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/157.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d8f8ce50c2e5323bf8954b9f81524aaf49ec90cce8204ba65aeb2ff733704ddc56f51d0e6f9d35038e2272de3803916b2d41c261b7acbbfef683192605a51f3c" },
                { "af", "ab23488be9b4971402df4f7c7dadbaad1549e8fb96a194bda2883d91878b3456cbbe7e8e7f05ac83cdb0c2425f410d8ec90bc1f671cce72f24b34e0d96c30072" },
                { "an", "055d125f974a21a22e607e8d05ec5dd552ab259ce712bd163350c72be18dd82d41839878ff28309c70ef1a62ba6791ef4a7f0a48cc69c5997211d3e5bb655466" },
                { "ar", "eb202478aa843295739149684572b8307766c19ab5bad4314a9a4f766d15bbd8d9b3f80ac985dc8fd2cd44b526ddfba35c71931dd60c076a9165812619b351bc" },
                { "ast", "ed524eccd071aa25d6bdbd7b8c310bbfc7b0f9ffd5002ea0b4f0a636b591aa1f2251fce15ecc4596e1bf6d9c0dbf63f0eaf421a3c2e0f571dedb4b03ce654888" },
                { "az", "3fc6db9a946cbf26a66f0d52fe2a57f77bcdba259cc459cac842c76459b22be299dd50a9f269adb8f20fe9411f32bf881fc13f9c8e8db59d16b46e471619f213" },
                { "be", "c98602308555ab4c4d6e032c029f5c06ec3b9a6a8a49e3aba6c098e081e88ad13cde8537c7236ff6e65ed05b75f77acf2bb6bbdf7a324d6280e1bee3f1eeed16" },
                { "bg", "d50e606b1eb7f1d117a6d5d1d9144b1ea161d7a16993684f013c96d6885e3af27a76de2071aa41b5244b61ad007d9c86c9a0077e326e15598bd0f8ccf8d29fbf" },
                { "bn", "dff0a5c8f49be8f0ed0b684dc5ac8866b0977d9fe2371017fe0e968d224451f28159fb45083f49a8301bd5c468103139a04a1492446cb8673dadcf665f8bfded" },
                { "br", "3c7d7d7722a265198c94951014ce3adf77df0fd22542b834c4af95e13573cd59d0ac7e4972b2b1e17a66281a166ddde6e258a88c03df8df29b73d0b500360b37" },
                { "bs", "b546922ced72fb90e82c51a0076aebd34a17aacb3ee109f78697cb67bd08bbb1124ea147af4dd755e0c19ee8915d22b833c07b9c871c08945dbf26e711cea604" },
                { "ca", "870699d2d225e10c346371965e5225f057181a9ab3759151c8eca7957dd4f61c7a2323fe3c45bbac7b73aa51d3ccbf3885eeb2720526aaa2fa6fb943541d6357" },
                { "cak", "8c57a072c1062fb47b8ff052dc7b331e46f271dbd755380c92e9b4ab3bf0b1b318efdc7fd456cd4ecfe2714d2e7eb2eb4cea8a2f1df5c6ccc3dc21e79818f9b8" },
                { "cs", "2fe6e60eae4447612dd6f4af8dc9031954c0987e9ce534abf59a0a157184568e3a5a1ee55692cdbe832342cf07b8db7def6a427760d7977c3ce30b8a40355255" },
                { "cy", "ed9aaf0d41a97e758778b8b6b6f9dee29f0bc00fbd2b0539a628ce65cccd6923463dfc7b46b45797f64e2d7948187cbb8e5ca2ec90f8504db65aa130d81f2e59" },
                { "da", "202d7a893f508a90f64ae294eacdefb33b0f6a49191d7c7ccb4b40febdc08cbdc92a7dd5b015d3ef00d0a642a37ccf8387626de8fbde234a92c71faa41f3eca3" },
                { "de", "10c51b5524bec055bc4102e238f8c1f126ff17a8e4bb3b6d3910edfcf811b3003a2257aca2d71328e0eecfc4edf2868c6514687a83f7fd68eee3909bec3d660a" },
                { "dsb", "6db87af843751019bfec0b0ebd4ea8a653f536d3269c6725e7b2f98e2e0bc6eeb2e35ea9e66a93f91959c7906ab20d32e5cd5fb73809552c19f964e2a8d17385" },
                { "el", "658b3b08f1fa1dd94a33cf67d7ed9e33133fd903e8f60f2ed5cdd9a59434a9391b8267d1d9c35a6686b17bc531c7f2cddc2975da125891fb022769c9c09d46e2" },
                { "en-CA", "eed45a7becf599e8bad55dc39a13340fbafc036b5916355df4b188720804b51de360d1607149a813a862a45a1597eeaae8c8fa8984fd4b9e7c778e5dae63b88b" },
                { "en-GB", "c5b8a1cc22a03918c1c4de0040f36cecbb65c0df18b29e6bc0eba81fefdf9516823d1fedcfb6dce56be5c30cb3933f788dbddfe1c05de542beb3b0571bb940dc" },
                { "en-US", "53fe58dd253e35be4ea450db3aa35dc27bbb600fe9e2cf4efb4725262973db5289913d695456ddff11c54a3f93393591a3fe516bf966edf1a98cd1a544696d75" },
                { "eo", "ba1182c06ead7d76ba527934f5fc242296beae1a1a79743eaaa30211a7d5253e8a15fa5ccf1353c3fb1ddeaf07b9157a650f7a91923ed885c96ca054f723952e" },
                { "es-AR", "7bb5b52ea7b476369507f0d4aae9af2e90505cd32fabf7f250eaee453f92db1a6a96c4d03fb24d347a42294aee7b49bf46a28bc0626b365d6c180f2c5a5b896c" },
                { "es-CL", "25629c7ba48e16281c37ad088a3acacd9c4e2fc4ca8bcc243952ee358b9b378da0c2dec861512461f8c89bc6c77f4a56a02c6a7a18deeeddd53c188b378439e5" },
                { "es-ES", "9129bca1dc239e73d675152143005f3a8a4d15be1accd0beab263043e66bcc854b0991d6780a1d95e6c4aa1b9916298be5e0d7f21885b15e86e7d456d2ab5baa" },
                { "es-MX", "05b8b14577f11090027ed6bbf58f9348e9ce5bc4068ceffea841bc76a047b2a12a1e3fb69364c96eaaee4158e2ea32035550e5afcc9c8fe5856d0251bd13d4bf" },
                { "et", "19632ac8a44b16ef60c6fd2ec5e85d9bb2a102a2697b9c4b45b2d7fb3bf29959552853ba56a068b889c902024b1340a048dca44f0e04ea82ee18c837ea29051a" },
                { "eu", "3cc493b7739005eb5f55aaa8378f80cf4def3bffd5416fc3133afc82b13d405d1dcff9dc10dc7263dd3b0e8e727b42b82a11513d03f1b697fcc6845e3899fa66" },
                { "fa", "7b818acfc9e32868dde45bf0acbdf9278f8f04e8d910b970695ffdf4a7cf5caab411d58bdd8ccf9e0d3c97a33c85ee566d21c5f8d917257b75942599e521306f" },
                { "ff", "b96840326eb694c87a2cfe4b0ea8b63322672e0cb73247c8ad2a34821ff015a5d557f35bf91a93164b1a586456e48f57b63b67fff13c561617c14541a3474e01" },
                { "fi", "912bf0403fa82e71b1af266c75be894457d529f11d99e255b365379ec26263929b4a5394827df77b027bc2a7ed03beafc29ad821ab67187d05e73186d244d634" },
                { "fr", "72f4000fef37654950e32bc959560dffb6b8fc88db97c50df7080e699ba10df041c3205805b9b30cb8003ff366e0d571c45fb96f5d63493447fece451c7198c1" },
                { "fur", "eaf5f74168b673337021a745fc8365ca43ed42837fc7af53bedd529b14b0c8d7220a979aec0b851bbf90f4670af9c65d97506187905de85fe4312fbf681f3b10" },
                { "fy-NL", "d13e29a012c1df13e0f54a6f750e4cb92537bdd8d832e7957dd7e6b3e25284208cd790ad28c6e6b61f2164a10b5aa839731afc09a9f72e18783eacd5d33acb0a" },
                { "ga-IE", "ae3dea28301559464f2c5ffe1e0e4dba17b59dea5544672cfdb72a6fe6d840413ba6ec1bada02a147106c212755aa6d4597966095ac32c30a6493ad7ee6b8f3b" },
                { "gd", "7b0d7953330acbf296f01791e0564c36e1f219f6203951a6d7c8c60fae6a8e2d727fd282a67adcc2c3ea615846ae1e34a48d2f16073430b61d757b87e1bf3bec" },
                { "gl", "1eca5a567e0788fd502f34f921eca1b6802e0b11f25f5f61c814127ef91c617e350d938d317e3258143744b75b0d45e489755371ddc00bf859d716f771524e8f" },
                { "gn", "9d840d63fc31ab3f2c9e3eb6b9763a68f38c6e56dec03cafdef49b80e2e0f41d3188681f581cc90f2fcf75e2b51f61dc7ea2daeb20880cddafad7975f910deea" },
                { "gu-IN", "486c34378fbf27f5627ce7e8e5c9f96222621590a799b42433deb614aa4df7e4d3bccd887d4eca66f98173a2df49df65581135a37163c216cffab1859a22c773" },
                { "he", "faab4917ce5b8cef42b6e15b8bd5f60270cecee027bb09c277b3f1ffbc072ca00eef340b04b86c3b1d024cefb3a133543ce5d72bb08261ab74eac4f13a4cdfd2" },
                { "hi-IN", "23bed351f40ebbd79a5fcaca2cf40bc87a8a19c85e72f706572d9ab924fa8535b0e5c421cc29fb772e88059a866893e35b669fee82adba23670411d391a81a35" },
                { "hr", "5f299588ae0d9cdd46d1a3d7aabe865f03b21aad16eaf7f4d961ca07ef04b769d26bb449e7a7ec8e971ab0ef0fa1b10bd81966656017886bbbf39b7d1833f92e" },
                { "hsb", "a6df1c97da66f35720a492a940602d5e3e71eb169a9b4fd60ca789d150541593d168d0efdec88f6b209e251b6ef1295b4943c5f23bd70937e90aabb331c74a37" },
                { "hu", "5567aee343ed5d54407664c9a430b55c36f21381794ba22406dd5b2cb13ae8e3187a9d2a25868bb3deeef06c62a4e1f0dbca53f12b6a27245c3697dec57029a8" },
                { "hy-AM", "0d7831eb5ce3f1184d153217be95bead7e765fe53a87584399bdc8e957a480c2d2f0ecbc1768724a026d38ab458cbb0f50bd419e2ebd6c7097c39cf1b5644ff7" },
                { "ia", "4ce1b605abaf6be8b066af040a90cacf853bfea80863f65af50685912163aec667fae614402d018fc9e485a80b6565cb0bd277446202b0e471f83694c1305784" },
                { "id", "0f13ec68bc444cd7b6d29214eb1ed74941cf33c24610fdd243015abee0da3c9d4a7d7d0e77ff11bece2c4b40ea5bfe0b989009c5677b95e871e7b76404c31b61" },
                { "is", "0d00751e58d0f62e46815cd1487195205fea4c66cb12b03f50d54f2d9569f7772435e2e2696450f5a885a7941217f6bc8d1fbf8e0ade329814cd4913261c59a0" },
                { "it", "a5288fd1eef69392b61e56b87c564fc4932cf84ecf5fc48a896bf978aa97b276d9472881da6d91e64b6c9b049c66252b3be5ecb4dc48ac63e2a1825f2f83baab" },
                { "ja", "8eddfc5ee788c88e6300562911b8028a3448dc3d96ddafc1490567ae8c03c6437a51be2fea5fc97c0d9b534e0ac46091155ff6137e3c43abd8ec83bc70900fab" },
                { "ka", "4641a8d654daca2c0703ecfa4765bd7fc09dc068b236c7a8eb25e2b8cd55c25b7bdd93000277b7f176039915f304bac4faeac22d9af47357035dd8de5b7dc9d0" },
                { "kab", "50f47888432c19c1d46e22c0174e977cb5c352919c3272ac3de6c39117a556c418f133cba60c850ce41f560e4438a5014cef53b983ad27eaa684235ef6ee3c2f" },
                { "kk", "b7da3103502db480d8e1e807e34fe88bc802981ff92bb98b7284d371c0931e94a17064180319cb0bb14900f282d0792bf5ca502da21bbf6ef374f1ccb4aec8c8" },
                { "km", "1bc80e00fc2072e1fefd69656d32f86982582b245959960a0185d2417ee24ce867c7c416367e4ef0f7ad058b17b32a1b3a649447b8a4b83270535ec5e8565290" },
                { "kn", "3ff83e90e31bec6f7f97f00f477d37b6769a908554d7f12c5f744fff3ab31775e7859a0e70adde7d0c15c408b525b788fd90b23c06106a5368b63bcb3dc5dab6" },
                { "ko", "941a79bf98a635ee5c4eeb04ac8357f203b7bd5f746a6aa12aed00f5240d3925ecc6e2cf789387c71c842bdf0ccb0837b1068d997bc4d1c2209cd85714d4227f" },
                { "lij", "24e63268f096bbba8fee49786f99e6d2c221acc3879beb38b6ad397147d044dd78dc8de34e91bc20b1ad23dcfb2e5b0a4e13f17d3b7e593cb921001dc64eb152" },
                { "lt", "c3a999f3d5f947897766139962fbe87765f0407d05020c51b33e3ed51cf86569ab4ede6b657f025df11c403abb898c975202208e6ea78a37e2fa4854894a1ef4" },
                { "lv", "4aa803b876d284f76debe8587a566c9ea1e6980f83222281216f1ac9b2205482913d46b3cc14c3a5d37b3fdbc54009e70115d237b024bcdd1a5b44c234e56e84" },
                { "mk", "4bd84fe752f64ad6c0ffb1c5217d4a3863686e371702fa2be8c232da475efd16a4de79fe70952eb490c4e6ad885635c2b6acbd87b390ea4568a65cddcedc14c0" },
                { "mr", "f65e0a6c2b4e9b12332d2aade2bc5787facf458ad4d8cf9aef01debefed5929262ae1adfb3665ce14debd1006a2a0f02f1c8196c3c748f180062c79dc2d331f9" },
                { "ms", "59974cb89e5bedb81a9aa5dfff6ea7b29fb91e4251ef3ef3ad01f9035f724e29f785a74253b3ddb04d87284fb749f4d0486422bde6b6ef13e3f596db1b26bd26" },
                { "my", "d8ebb93e21535ccc9ec0a56fdbdb2fca1727c7d487c100675d7d62ba204c302350b1a0c7f33c3fd65894669627ea8710170b2909f7f9ff6919dceecffed0381e" },
                { "nb-NO", "1295b5bcbf351bc2a93f449b91e5bce41e7abfedca927f67fb863c1566628e92f56be30dd4cfae166aa77091fce90900d3e81587f51b247413d5cc1f00c9922f" },
                { "ne-NP", "85a3ab385d51fcb26b035ce1ddfdc6848d6f85347c654787d6bcc55351b12d83716410d0f51b9f868e61024db7f5f7b2f4e303873a07626c68a72439c9e8bee5" },
                { "nl", "c66b36afdac7d1a1a2d9653f1836980d0999c3e1447139a64a08c8d75a4e43ccde5d1c586cb182d434fee750ffaa9e49979fb7d923eaa1bd425bef5bcbaa20c8" },
                { "nn-NO", "6306f15028e139af4612f5d4199ca2af67f8b79ec9d1c08e73202669b35dc3b0f5e1130f31fc9745d621dee533eef8ab8c8646c6789b6eb26cec160ca50ec843" },
                { "oc", "dab709048ca045a3226453d18d40b69fc43e3bb0a3f6873a18217a86ec9ebb8e8d4913fe17db5c1d27900a943376a0a382a30fb8fd86cfa472f5f6571f240d27" },
                { "pa-IN", "d4e30a74fa67f4a96a5c3f61344481c15af487bd43f9cbbbd6ea5f3c134138c2b46488b7feae0489e390f101b27772a9a649497b87e476c0a889bb72403779a3" },
                { "pl", "18a565771031dc0561c3646f4ec56119887e4a0818d6be08ab05e8ca2727207663222e1859a9b00ec8900426ed670f1833dad4aa9982c8ff23afd19d58d96d2a" },
                { "pt-BR", "926c26200de4d1629228d4b98d884ae4bc5013b59688de367cc3b1a2b17e480bd7344d433145ca3135372e677beae67821dc73822e767a708061ef001a7cdf3e" },
                { "pt-PT", "6e12fc8b34ea009284923d6653a28eb2eb4fb193a83e4204997175a64d07f6f73851b7a74c53152741ed15f0678ee5af0cdecdd7f81cae92ceb86a520a7ccbd1" },
                { "rm", "f9da8e545b96433a91018893826503168a13fa9c5ba837713eec0e8a164232b90fda89e4f91963e3055626b8a64128df02a380ce3c412ceb56a8d65dbed226ca" },
                { "ro", "3b16ca33dc97d62e79ec173149b1a15e6f713a8d38fa8e2bf56c35deb52abaa65d7c7ee6167771dc942be5ea5226960443ad6f150c6368979157dcafefb5d57d" },
                { "ru", "f6db6075118879a2223204c0f74d5cd368b87c65e2a75ddaedb29e5dedf6396fa87ab63640f2e0a26b4209d0d283f959d9c384dca95bb71dfa9e4147d7e7b8b7" },
                { "sat", "ccd3892c6b25ce618ab20609f78547742942e9c052c89216f223852bd9daf51356fe0a4b7079c0aacea8e012ca4e04e8c96163143c6adf571fadc9c3973b696d" },
                { "sc", "3040cdf8cb4d01293f2318283f3edab3334893b7791e85d8097562111b6967180bf95918ba7c9eff6fb343997d977721ffad278d1b0c9601b399298a6a8641cc" },
                { "sco", "0b3465a51640591e2f38ea661be67c07a5df1ab5d03158db8822e0eaf734b19549f4ed9728400963775186f9e7f4310013b1b71d60f13fcd533b82ff1518e4ad" },
                { "si", "26994369eee8a9efb6bac748ea33cff1febe9fc9ed16df2fe2b72a4c473e4dc781e1a3fb63834bf599777cfb3dd8ffc088d9c4f6804a54bcb34a731ce02ab698" },
                { "sk", "6921e2c055d6c760555008440f80cfbe23edf30bddf60525deba3c070ab2632ee4a496110dc034bcf5e4ec6cfb7c2ea8d0f3f4445b903a66e90703f57a205c75" },
                { "skr", "0fec5f4f190b97d376168e5b6b11df9e9300828a7f9d30f91846331262c2c0221e469a554fdd489aba424e84baa01131776e69ef48564c2eb12a2980e9da50b5" },
                { "sl", "21f39625964637b4d95d3993217da4b68d82e8472c16f95130c8609df95300b4eaf742f390582dbea46340f125f2033c587e86552f0b88fbf0c4321b6f0031df" },
                { "son", "63f758a9ede17d39857801af60883a4b9b62f1700910af9a140c8afd5fb656800c8c8021d592150bd6a09f9e95eeeb50d5ff022daa021fcd1856461ceba57380" },
                { "sq", "f4f6ef4d40bc6c38baa235e7a4f2fd6724f49402361f7da217df14027a5a19de16e7444ac6896125101289f04e23bfa55c6355207859cdb2c476a7ca8e089c05" },
                { "sr", "bc16ddd809957d8e24b95f20ed086232153cf691846fa3d7482c968a9505aa21b71ce2adb54097292257fca8b8005a59be41f3406f8081917d2572ec7048680e" },
                { "sv-SE", "0725960e3959dd3b2d4b6ab4b622d6c141250ea28ad831c908144e799befabe7fe112f1db64582f0b198196974170ed4f8b36858c37ca3938c1e46fac9ce866f" },
                { "szl", "d9759f5b2cc8056df31a658a4e8d36a0b145730cb6f5897225493c90e89886a4bbba6dc624ad05feafde0d0c3a8704bc818d379591bb2194821be39c31520f1f" },
                { "ta", "068b678f442e3fb9b20efbfe9e6fc5f0a561b28a4a3042621402acafe08582261ebfcc528614917edf29ac9f8489054695f7401ef74e357b2d09194123fff545" },
                { "te", "19fb099e5e9d454d879ea44bfa7ca80df4ad9921545f8e675abb3f9302243be0aec4228b46092930c4e948c1daab8e0bdeda44092e1725e5fbf1da564bb71aa1" },
                { "tg", "fd4317863a1e9a9e979f5e51353787438156ffda1eb8747bcfe455c1d2a3f190721972cfb85bde13878a49c4d2e2f45fe36eec1293eeec74a8bcf0c4857c4b49" },
                { "th", "2dce8cd562c5bc33033fc34400359f86142f9d0281697df1fc229e67aed9b30bde4d8d2ac7bde0b341e485e95d9bb6d5cd87ccc4c0bffcc48d8a3cbc74bac295" },
                { "tl", "70f9fa204a50ecbf87658346e56fb487bb7618f0014cbc249cfa41e671e6978663cb1a0f94088bf7abd36d8f51323276fb930f174ec49a4f757ed0aa7f22dc4c" },
                { "tr", "c0a68f7c94ba85141109a2f23fc9b50d8eb8b3c57fce6ece6fb2a54d559b4199b702ff55df2665d50b8de92ce03af43fc0ac160002b5a97cb681b40002b24b3d" },
                { "trs", "09dd297abf5aafdf726aad884a355dbdeb748d1662c403910c5c59ca95e583cef631138d3f3b2c255d365b9bcc417cb718a703c43a5c8e11993059492538fdfc" },
                { "uk", "d1c367f483b6a21b898e17255b5f62ef7d7facd9d967a9e3153200d0a74852924ccd136e21a8ab08a3d0b2b38bbe1b59a2582a271885774550f204b939522ccd" },
                { "ur", "ed7e463fd3cb3ff54e9e46b95e1104b459739078a4907a3525d0406f41dc360842fc233355ea801a9935a99f94da4875c97cab2c194bbd9cb4c894b2300bdad5" },
                { "uz", "1e3cf0f55d8f231b8c091995c5986e4b611b010d44641828223fa8407b30b28772368262bb0082159d394ad3751ef17c2fa1b620c384587fda9174a9d09d7e98" },
                { "vi", "95e6f42008933a86f94700297fef332f25248fceadd59b6e0e61c065cc662100921f09ee79f9e5be430b2a3e40fd95a17dc819024b38005cf84cade40c097190" },
                { "xh", "62f045be0922a2f6ae73cb59778db6bda8dfdb6831eae61a8c522653b8bca149f1e8213e2fc8bb18df6a35a86831be961b2ab956102b51efc935de3630245a04" },
                { "zh-CN", "add28beced54c8ebf1b2263eb342fbc0e80a43542aa107803e81df8611e3fb1fcfade69f64dd0f6936284e36cd3eff7e660aa805a0c931183435aba582fae407" },
                { "zh-TW", "0bfa6ea434662c0e60cb0577fcf65a3849d111cbf45664796da550f4d3c55fa1be33e481fe4c49691ecbba7261fb12f51c2a390bf0e6e0723761471be36c820e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/157.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a3c00793c23c4ea1bff5e94cacebcc1ed770404504adef1fa14b01acb88e24bb5b965f1e86a353e51b1a66fcb4d13d3df327679047ff554e9a3236287d68b592" },
                { "af", "4a96b49be3f8b10c056720dd01887bd88930126d29a8ecafe8bd8f6ca2bd5643e6c9e97c182512034c5a818ff25c148e9b9b79814a718e30555c4ad2c8042682" },
                { "an", "e267a7e0f825296b53539bb09ef05f4c5028440b7d9da6c94fc407405b0145f8bb1a1c10806d0c39129c47d40e70fa4b4bb1629441a054e28dfc4e520d69f987" },
                { "ar", "987ebe6ff3434594135df746ca5682e795a8c6135cb92dbee44fac80e6b216a12cb4fd312b26dbaa53df136192807b7aa8befe36b0ebb54a511a6afc36f1a5bd" },
                { "ast", "b73280d2c595400f32e0934623d020ef6a9f636dbbebeadf3ee72494624ad556bbe7bb1e04d0ec1dcc5e152479d6d065c480626144c135a5990fb1da98dc2840" },
                { "az", "8ec3065a9b481d1fdc0be31318832fb90f790f46592f21e68d6af419ab123236f0fb86680095122630862035a59a7aa3840ffe942197e5d087fc47f6fc157a04" },
                { "be", "b424d69092a4cccac85bd46e05fd8101cdfc1b081e85ee924451d74889a16cc58bdc76014463ed4a05fbb955ab10aac77774546c7cceea3eab3646b5c0d30e3a" },
                { "bg", "ecc0f619ef36384757434c42959b0d012045ac1184a1987a8e730fbd7df115146fc0505546e95c6e0c67a17ad88a89cb6787d26b6b9a04f8d6c4830aabc7c67d" },
                { "bn", "0b9fb373b65be7c2d16ac83c4fb7f2b9eef7102dbdba3be1af1a439442f0b0d025a7a2353365d42d631d3438d10bff25807fe272110e0f0465410524fbc83464" },
                { "br", "212131c214e2c94bcbeb4e7b5060e2ae3cc5ce6810961096cd2525541cee9395d035f33fee493e6b1f67d198f171805ce84fef6ac02a687385f87edbe4a1d3dd" },
                { "bs", "a110876b970d5b554dacc6d12db23a14e49f792360b8792f4330bd2d124d1413f3e7e94a8f064481abcfa1a0f48ee690135f6cb844801a26e1190411c6e67ee6" },
                { "ca", "ba26e6b75821d612345cb9d69f5c43dab889e9ced5eb03c203580bf7c2a0275527f91b68d22e3a0fa79966c2100c02a098bc03388f1b7cdd0bb08201bf5476bf" },
                { "cak", "a17c29212bc550bd918fb755b0e653e58f6c7ca7c784a5a90eb397d1d6b5c60b2a4ba97e8631b67a3579e77c0a3d481698167155db4019305dcde065519cbee7" },
                { "cs", "8abd8c146b2da602bdd8387df842f4be7652cd30d75de61545a922ffafa7cee113b65f1cf142aa34198490207892aeaaafc5870cc131fce81056b7858d0e033b" },
                { "cy", "5f2caa57d4187079a2cd0c1693928ebcf629136f81e1826106d7c62493c2524754ff1e6bba1591e004ce18bf6ea37e40d234c79fcceda0188bbe2c8192ed224e" },
                { "da", "3b3c5bc2ef3daf1ea63811b5e91d43168e2dc7977ea9fa72ef1b4fa621297ee11ca251c34cff1369e4b908a59706f32dd143eff40bbe9f25d114b4cc6a98d4de" },
                { "de", "de2239227b95b5d75b2a1b843efdcbbc3a01d9b60cea6733a6b65b5ddce38dbe494af9e7386485f5052db2d85d411d710498c9526d82a5a28dbb60b898dcbdc2" },
                { "dsb", "589b02eb1cdeb58e8d25bc352019a6700d7c40307568ff50f18c32f8468ea9557102dc859c36a526ebb0e88a1d7d9bbdfab715ee46f4a5b1eb526eb301ef2637" },
                { "el", "d0736bbf10c1d5c8a0610edec4e614ac2dcf099efd11bece190dd16d4635fa3642b1c3db656429f036556681b010fefbdde21a6f9dcf3db8fa05d64b36e7fc0e" },
                { "en-CA", "ce144875c8c7983fb3780143a1181d032e27f3679a03dbd49ff252bca3b8769311f5fc6b0e88766ab7114b2a42afbd6c5529310ab78b4648090bfda369bc656b" },
                { "en-GB", "ad98afd2293635dde8410af280986bd15bd8945775045668dee313cb8216b30b02eb32c67b8b167794fd76898190718c219fa0ce749496233fc8c44959bc92b0" },
                { "en-US", "8b3517df9d9e55a00aca4aa04023558030c8c8704d8aa0bd684607c19c49302ed778ee9d34d4b6e7fba3e6854df5c006bcec79c2ab8c024dc1cda8c36c85204a" },
                { "eo", "dcd1471b9026910493fbc1069e90235bacc46511fc955aca104be0ee7e10031b11d70d00b6e7c330f6215b0cfcc9ef43e391deea93c32c18a8b79c7ad1e7f5c5" },
                { "es-AR", "be93b9ccc88fe60c0cec5a063c0d526c3aa4b588d771a7a23e684f000c63c933848a4318dbf185cb723c4adbaaf46b9c76f9623a73c99b606b38c83e2c180b84" },
                { "es-CL", "8b8ff1d0175d4ed55474728c727f83f4358e4b992d08a57b8bba69c9e6fac60996bf4d4cf1679375d84398db5c25eb0f1f0224f2063795076381935495708670" },
                { "es-ES", "6f0d20b9f1f1c66c7dae32c046b7db2cb00c6507ae6f544a730a94bb86752f7f044314291fea9380a24fca76062c2163a9729b326c59130d5e66857abc8c5790" },
                { "es-MX", "8dc0babdd707360ec85397ad8a8ecb409921755ece244c2fdd0d993df6d3993729e32a9e283e7e10475ea09b8aa6d16324c9513a8799ff83edf5d8372d4a8bc5" },
                { "et", "4aae34467ee8a34f56081b29f584bcc1f40c088b238a382ffff3b1d57b06304555b01a20678e260c301a346a5f86bc0026fc07ebdb1456e99af42c299d043529" },
                { "eu", "7789bbef8ad974a6b62ff684f1b652cdddbc7c869286e5e977d217750bc61693068bd1040097c852da60a5479b9c6a4a8c00c8de6e3932afbc54bfddda9a8cfd" },
                { "fa", "aed295305758aab09538fd18f56d1859accc315008e2450a907e1fe6b52a46b1ab30555c59c574d93cce2b04760433c09c120d404bbfe8e07a27c29513298e30" },
                { "ff", "b46d665b32a8def29c7e566fc6fca1860ad47331410fb1b56c4fdbb57b3b29b2c446e9ee916e4604e8085245af51a27d6fcf1994837a0f9b4c3fe217745c767b" },
                { "fi", "380e6cecd78db7ce336870f1954afd8413f6b843f34929e6e9b2db5f80a9e19aa94e8da2689d47716239e3713010910ba22e14396008e8a88ba2cb91d1868a4c" },
                { "fr", "d914a3038bf33ba9302265cf4cf0533461bc926a58db8c48a352725660fd87a45b27232bb83ae3c4d995df597b73ba8c554605fa4d9e0db06e4b250ba0b46bd9" },
                { "fur", "605eb0db20a2a6dc388315f4dc3cdfada9e3e9fb4246ebe4b9a5a54eaa52b1200656bf841e540e7c1cb59b9714739a177426fc57753ab6eeffcb9848e1644634" },
                { "fy-NL", "c251eecff2f6ffe7a9bca8defc9fa6d4953fabad8dc668f4e8c418c1d92cd6f486c1dea44ec3f14e2c77915d1022d151584fa6399d59f1d4207ea16baa2807c5" },
                { "ga-IE", "bb1f9c117d014c7895c643f97ed2d2d7e82bd5104919d3bbe5eca1e9ca9ee233922bc07583ed9a10cd345535b461a3c1908f14947803a3bdff6d0c89e6464d91" },
                { "gd", "c57323c9175ae6fee8d0fb84c660ed7f3c7d93046c9a41b0e2b9e930ef4b499c9fa3f46306c46860f6118398ba070baa96e53dbef3fe09ebc72b8b820d173661" },
                { "gl", "99e33eecd5faf9e65a8a29a6b9bcb05ff07e10ffdeb999833f6adc1495435333c2e26096c602d047fcb2cadf63d716c5d7c55100a2c04df6b6cb5f1122a323f2" },
                { "gn", "704b65829d6c49f599ee6b98ef2aa21d305ba836bd0779705e9332f2aa8a7f60d83c633b4cb71a7b64aaee10e1e613242196d8c11242de4e908ec545b697f298" },
                { "gu-IN", "37d898621187bddd7544cb462362cc56e15571e20e8ef79f1c9ccb606cefe45c4561e3f01086c90736a2b606ffa9063d6c290db033477f3c653b52f8ab3e1901" },
                { "he", "8700217f83312651ca28c52a86380e50064ecc72a80f413cd936d72a72eaa1fff1119c38a9f67bc548ddda1c7ecde46fc9e5183b16ef43371c1479da05549c12" },
                { "hi-IN", "8bcca69751fa536722403b37aa9b92e9457eedf4379e0cf63d1e0725cf72985a6f29305a9eedc845c2260d52321389ba73167f5e41f44def980417791faebbbe" },
                { "hr", "37bdf61560f887c3d3e7c027c55ce54007bcb207d20a1ef0a530b534e0f480389714cb01f98695d6537a2604d5cbd78908ceda38c70aa60d0b6072606393f5bd" },
                { "hsb", "2340f47742b8570f2f4f30366a137c466483eb9ca20e36c0565d838f318202d78f2eebe7f0b1331fc3a865fe5e192730d2c63c13b5dd4756d730610b6ea3e7c9" },
                { "hu", "04d0c8f50a4e478908107bb70f30424521061f376aa7df154244095617364758489ffeb0eed36e993188687e3bb9f3c70b663bffef5fb7e88084b6ca2499795c" },
                { "hy-AM", "1f682f8447f5bfbb10da69a2544495955c431e57e23c80ea016589ef4bee732b3603a836365a460aa5bba114d20a6424cfc6e81fd09c57c2068be19f7dccbb88" },
                { "ia", "91b11fb3473134dd455a8583a423f3b5932f6d4ac911e137f6eb1f48764e6e9d4d625c50117fc94d6f27dd8149a271ad88aafaa1177244d0b58076da1d8f5e72" },
                { "id", "47804015b3670372a49d09330da55ca47c981a6d7cc13fd5a6c5e8003b340eac7ff51a1b3bf58bbf7504c53d9f5c3fe35239511b48b9a00cb5b71cd1b04c7546" },
                { "is", "a8d8738165ea396e651dfb332afba7770091c1cfb534e1e33613cd2a258e18268f33e6a47709b52493be4ac84fa004cee0a65ba88cfdd94af6f0dcd29af2d8d7" },
                { "it", "ea1fcc7fcadeb79ff436cd611126f0cb1dadc6e19e9636151a81d17236beb2c498aa76ec573f6ceb44f18ce7457654484b4ae31bd79d6cd124f906ff735df4d7" },
                { "ja", "76b20029086872bb8201ca3c8b7fc3bb3644e3bce159794739cbe5618f8e7fec007021dce33fcf00b4e36aad52a00fc1f07b94afd046ec8e5ecbc5633522e76b" },
                { "ka", "88168c5e2d9a04e4788fb4871271f64e8a4353b1b7b91fa410b9f7f8396d9122aed40e56b4a417375eeafbae61f8c5e63893e7a8143a8f02f9262a6adfb53deb" },
                { "kab", "26076ffb77c8bf7bdf1b9c351de72c40c7df73fe6f662ceda38c29a711ecd6c95d4c38df9e5e2694416b68e54fe687e12eefaf60e02a7b6562811a919c9007e9" },
                { "kk", "58f875c4fdeb781ba94f74923e48f1aeb2695b5c868fb40521b15360d068c57e40acfe864a1c2a7af2c929bdc5912b9e5eb16e9959b39e25ae9f4fe5feef8f8f" },
                { "km", "7413c474c203eafa0184e437fd2afa3295b7e71817388c3308f1e50a66ade94f59ff35cbc55dfcf5c74a30d824f36870e8fec37f0ba85bf5162b10e47c2f7309" },
                { "kn", "8d6375ce4043e9c54d91ad4f0c98a6f7e4716c678b644351fe67b4d496e5c194900c1c77196d3fa3894829db6aa0a88eca95988031577f69385bd89721b8967a" },
                { "ko", "a35cbfcbab8404695d6e8245ab315c4efe4e4d4036c3a8196edfea34edcc2e6431e46c713c7939ba3be74346a8b03685216f9e6a1db629028719814e5401ca12" },
                { "lij", "8dd4a52872223344dd964386d7bb2817f4ab609500e12f3d78b6c5a4000abcc067313e89da83fe0913c36874bc9916c0ea2f685dfa542b9ba34bc64c2dea5e95" },
                { "lt", "879cdf1e3f4d56c42e9de01583fd3a64c72fd75c53b595d419bf65c8e6c5932e541c2cdc8b1e4673c6d670851a753f63201ce4410c754300fbbdff161af5f905" },
                { "lv", "8190b23ab5fb6238e79c4ce1e086657612fd12161640d6033d6736fd6f8855cf757eee790c0597b9c6786dac9da931bb348032278c0b4eadd64ed1b7ce17f3e8" },
                { "mk", "9473af7810b3a1fed2620974480a23f6378e39690f08f37458e23f78b045cb7ec7a7e1fda0fa335c0ed34ceaedabd42cb423c276e6ee0c72f3db5fe91208cc3f" },
                { "mr", "bec59a98856c1d55255276b582343a2a6242b5c5264be6b5ee9a4bb9d3ae1074666579e320706e7cd3207eba91879ed7a0d2acb5e2fa0225ff5f4d72ac4af94f" },
                { "ms", "d88d62c40fe3c2f362e3a39debdf9ecaa52db39b1d214080913f946a10ca612071a0d35e8a2590bccc83219db8ab8c96d3400f28a6606ab1db1181ab806c07df" },
                { "my", "d4cac9e87a55371bedc73bb147c34938f20097d7831c1d0773d1cb7b0c23940e00f53e3880970174ff083c2a83e27237064f3d6eb71558536d0677a1dbb8d8fb" },
                { "nb-NO", "b72824504b5c582ebf1107ce337fd5d8a85836d092134a1f758bef068b1c9dadaa291a2fc0d9e2ad8ba403bc41008067fb39e985b884d2125c8c557b0daa24ff" },
                { "ne-NP", "cbc571afa482329cc6ca4e62a459389866d6cafe60f3fcd916e8299b84c20654dc5c0dd3a42598bd32fa05434253a7bd17d21469bdea6a6e08f92c7496a109fa" },
                { "nl", "c99cea10407464a15484b84b61b2ae4023978a1d6cc07a442d21fb4b5f778741f8a1d8c2e9977a7a9d4746d2ab56d7542efa0c2ecc76e54cd7dd31610c8ed73b" },
                { "nn-NO", "e549041a321337ab0a6d605200d2d3f382e2f59ee5b3e23ce9d7f6b7e1cf5b5414459be213aa47d01c9ca7fb9a0e19c47ecf1c5407848922c83bfdebf70e051c" },
                { "oc", "8dd137ec47ea242326ecf0c9d3453a058b15f116090f6d425c5769ae0a4b1778ad878ca529318ce9ba27aa668bfddf1306e95a0266cfd816af9bd9a0d42bd4a5" },
                { "pa-IN", "01fd11ef617ec11f93753175105ff76b4e0559779389b16d958e34da592adf4b45f11025801023b4664b0c645ef7514a3a785ecd3a2afb72f243341b931d04b8" },
                { "pl", "0e78fa530b06465a67f3a08a9b454f149e3e1720b59a27e303bcbc8495bbe6e67cc23608e0f78a71868ab43c58fa8d419877adb213f8611f76f58a29e0190bf7" },
                { "pt-BR", "5aa1da0d741dd51e9afd63bc20f12aa65dfc7e3980be69b37e106a8a7a73bea0382d028d7d5d35af7e4d02435a1abe77c6e57004d1fad43232bcb1c8aa0cb72c" },
                { "pt-PT", "07c5cc83119a265fa7fd7084a289f7d21a33f7c622b96ab7b52792728bd54a8151d261c2b7fdbdeca84ee11a3ba6fa2ac0748b1545646878b888db79c52fe426" },
                { "rm", "f6084680e1872c0b4454847bdee47795c20053a18f435beb7d67b4c5fa4d638c2d1fe6ad5212a0f1c5b331e6780679fe6d45206127119dc932188395bcc0c5d6" },
                { "ro", "6c53118422b7a30b7fdd1d4ff9ac9646b49d22fac8cdef732ba9175793694cf93ac55f5e225a85a4e6e401179359f683984038785c3efc77ac1cf24e2a38badf" },
                { "ru", "006e02f19bcef9b086e1ccd334c82315b4381f18a451e1b72591e132dc770406fdc4c38e72a532486d87c460932259a789b4d77b3e900833f260414893ebae54" },
                { "sat", "71c5afe69baaa46490beb4da31abc0e1f5a7bcd56f8d2332d3fae85c49f0450d03c5fc3613eb07a840d092e4f1ff9971db5e7f9e462a428eecdb50b3846434e0" },
                { "sc", "017b4b086c9d68d43cbacce955b063f298bdc4f97a8ea6a54db71312f0d2c612d43ad686ea4f9e5c205f002abdf2d9fb7a3d11cc634cdded2ed4de276d7fa5e1" },
                { "sco", "4224e18078a01ed429bfaf4dae0c2834934aa1851aeb3f1d1403aff2056b53eb51a78a04254ca8922c3507d803813f03c1b66ba99f93a2c69a4fed59cbecbe46" },
                { "si", "d9f3810ee77b756e3f1adfc6e89ea6530521c36146787e4268fed87cf8df1bdba2a801976841a68d5e7d90b79abc2dd1f4249a78d699db3fe7705d623f66675e" },
                { "sk", "20ad1cc0e1f6d2f064b17904e5937b5e2643102a92b5a1b669912a4a73cb5f0e8096c90d8eab7a3b1bc91789fc2735d2c78da51407a763a8ebd40b940b30f071" },
                { "skr", "2a4c760ff1f1a20c238f3eb125c0f316cbdb5bd78d5bf08757cfc156a6bbacda2976d24f28accda8b0d7361d114c07867c0b63c24106f1b63d779c165ac75a3a" },
                { "sl", "9da79c21f2e91fb88fe68025a63354c881a8e96db1b1f0091d8a50e53df78c4e2c251cd4075ffd6fef6bb1deac5be764b12332295839bc56623ef03d0086e5cd" },
                { "son", "c1a32daeaf3039f3acc65c55c25cca9d45c7ed3b7fe23c54db21185952c1ebdcfabd3379f0cd4e49c5570e124b2c55283b2f1c4b681849bcc18d578fd55d652f" },
                { "sq", "0d47a142bd8927e17bf5ed2ea725bcfd4aa0280545a172788633f89e956e6998aacf5087ab46997c7f84afdcf582227a125893d3886fe7b30102bfce06bb504a" },
                { "sr", "f298e81a49db9b1edbd30df6e1beb72c72f4fe0b22ce737c1bc41970ff6f3c150e27c4d09093303f9633c79ef729154db44a7334dfdcd7603efc0c62848f0abf" },
                { "sv-SE", "13bb10dadd10ce1d739a491403f5c1fe08cbe5e29bc53fe1dd8d7a27e2f7793696060652b54fddac5e33d97edb8e87bf6db18bcbe0aee77bc89df3dd1729f521" },
                { "szl", "4db34571d681937062adf901deeef82f7f6e086d2dd4a8ee3a8e48cd98738628d2e333c157e969fe2426c95495cec355f7bcccefb13b44496a9a228d5592a862" },
                { "ta", "45a03ac4f4144bdba9f68e9883178557de02472cc84521ecb1fed5a557f5cc16e2f80a6ac71d0f963f6951c5af470081b5b2179822e574bb2afcf2905bd4cd0e" },
                { "te", "a70001169d2a3fa89366d404189c476b6f0e4acd37723ba6e0c3e8d09e08b1aa886208f15c486da8db356ecb93d80a3155109720819c61124a21c8256988fa3c" },
                { "tg", "6f8ff7f52f0234806b52ff4c332f348ea62fca5ba6814bb1a72f27b7b23573ec1412df2c981bfc9ba1b3d4f1bcf63330193822e41ffef129a8becf8c8df217f3" },
                { "th", "ba8a50634189d64075b9bb9cb67fc0d42c1ab4b59bf03e09953b21bcefa9566ba90b6824317c4d9bfd6bf9aa809a47e61cd42fb1a7fc20838986f9659017863f" },
                { "tl", "0e128000bdf12b569f03a666473bcf9615d41fc507bade11912a2e239bce3e6298e16a46a4da7da85a99f9bb715c7e991078beb872186357ddb95cada22bbf8a" },
                { "tr", "468beb8abe1618a2bd2b29b2953ea8d8db475c43b1ce57238c5c935d711898a8a529d3d2ffefb5b0be984661674c44cdf404e0b80cc6445edfe5ec2f6ee50572" },
                { "trs", "422456d02c2c582c69bc8aa2a9c1b1add24f07067688c1d6c53137ae9248a50c0779809b77785cee06687909df142c11514306115d1a47ea51f894cef0d207cc" },
                { "uk", "24e939f9bf0e7d24d42b5c4e3f1e1e523e387514722ae6f0230788719253cb310c7dcaf64d2b59fdc492418e6e5bfead97d2a6ec7b28630e5f35ab1a4c5f47cc" },
                { "ur", "e731a8570e946c1b557b58e9e82b5e3c1c0c75fe38fdb6389bf406fa60683124ab6aac13197317519471a38e44ca9b8d68193ff1543233246f2a4623103ad757" },
                { "uz", "e144ef2e3f34bf24cded122705c95724a450f3d96113cdb937ab0fbc34615bdf4cf1625119261167de6e73d1c6a11f66b7eef660c1195b89360de8d473c5ece8" },
                { "vi", "c85b77bb65779e0b28a9b1e26368baecf2c9746b505ac625b7d3bc9926d58ad602a080ed6ace192f4991dfb3e799f2fb3016a1c712f2dd05086f070e407e48f1" },
                { "xh", "e65949f38857da5630d1fdacc6b60c252ba48a3700fa08c049bbae421301ed721e8969a2dfbd013bd4626a367981bb4e6d7ab3706e509ba130efade5a4deaaeb" },
                { "zh-CN", "47d77f15fcbe189c62f8410336186cbba2f37cf42d6aed070437304e2dcc410520a90537327f596afa1726226be0483c165e97bf7942db7f4cc352316ce7ce78" },
                { "zh-TW", "e49ec3d061275b4a4fe5b82b8b18985a326241f1710d06028a597920e10a78030646da9c9ceb5e0c46f3bbbe568a0ca7f9a4e491c6b82b7b1b65b689ba9a5ab5" }
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
            const string knownVersion = "157.0";
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
