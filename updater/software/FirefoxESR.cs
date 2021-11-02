/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/91.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "a9583115b62ec6e7a1baf82b8fbfd19338505da30b69f73e485bf5c5be2550eacc6527eb4063d0d80ea6554ab43960b0255dcc10022fdb60e403aa5e9f734fd3" },
                { "af", "e36ebf50a76b05d7927118fb546d86be154bade1ccff62dba2d63cde9a7b25fa5446239172722afab91c1454f8e6a24f232d2e09ae0bf4bc1d692da7c8282677" },
                { "an", "8b3e97afdcdaeff1541215473ae8eb560bf53a7c617d9242b0770a8879dccf876d86aed65b110dfd5203200f104dc5ac16be1d8ddfe2a228c640ee98f6ec4c99" },
                { "ar", "b26fe0e5018d371bf7223776d04dab7f1b6ef7eb21b108827930ca33478b54bb5ab525c93f3219e6aca6c8e6ab8b27cd0334ca1ee2c237c477232a544fb4409b" },
                { "ast", "96d5accb10ddcfd33b4d62325f7bb5c2635ebfd1dbfd699ede5683e194972ce353423dbe7daca0730984e270b82c3d83bb8d7afe5a13597cc6d98c8675a21114" },
                { "az", "778b93db42596f2c07e231a6253ac86d1ccfab6ce3ee2b77f3e5a47c21926605c8cc632aad34a5887b445e3499598f5d7d26a34777c9c7c1352b18db612c7fac" },
                { "be", "0f083415419c17d753f5aeb57ecc56c9afee04c4eb7c16178bbc2d18267ce9be1e733305bcde377a3a0c973297354ee9c378bd59f29635ea289c440973d5c98e" },
                { "bg", "423b5441084c68270f0d468da4b4f971f9854ebbcb229ddea8e931370768939d4cfe9b3059434fb09f2f2c016c627d629a8d8a1c47dbc7f59fd91e0aab37a559" },
                { "bn", "b80cc218084714f0d3c6ff425efe07f7f5531873c55310c735f67dd57ce4ff4bed75a5e4913726167bda32599bd65c6f1ecbff9d3efcad3ca75e233019cc3b0d" },
                { "br", "dd74ca33a24c896a5dc109d63dd21f3cf93075e65d1f758ea551ac4994034d1f6c826afce3430609277ba2f337989eeacc2024c329e03086fbf4d6f6cd8711bd" },
                { "bs", "37d4c00707c55e9df10088cc2d5628e168986bd3ef7f85acf5ee47a43f89e2fb7437e1eca8206588999db5f53339be824227b17af9df3db654b8482f5e02a4f8" },
                { "ca", "6348c24f020bf8b285d790a1a265e3e7a6a5d211408c31b5bbb32ef2e9cab673f7c109493c8a973a5fab00fee513791bdbfca0c04361b1dc794ff47618f6cf98" },
                { "cak", "097e86a3ca6695313bdc8e746946cff8e18cdf5cfb767161ae55d1a0838b06cebfc1c2c2ef5832741f9645e744978750ce3c6beeff40a7b778d5429be01b4177" },
                { "cs", "0aeb59b2163cc8d9b0fdc0d0b1e483b6b9add045daa60d5bd2f4455be5d261bd3a3fbf9357da441b2a532e63cccf247b7c8a0499854b357990cd2f2b4ce514cd" },
                { "cy", "05c4166e04b68deb5086880e878703b09460da5b607bc37d677c78bf2f97828a34be8ac02a68fb82c64978f1bd4ad9a0830e265f7f3cdbc3ce92146509b94adf" },
                { "da", "bdd0458247f746c2f2987124704aecc820c54a0900e717732b1bde66305735528aa52e3f4e7845da74d0db4fd056c613a184422c6b0fa79ff22c5e5c2d3bc5a9" },
                { "de", "626b66b9f9d4ccf436bf56728cecd024c485a2a2b495443f40e8058a3070514c391f22d107e37dd2a4b59daeafbbed7c42749d5da7bb89e238e4dc6a28530e6e" },
                { "dsb", "9891c0b1ff49cbf668dc4dee3ac9da684357ad7f45a267ad797d6b1dd8d4c906b899b5fd2528fc818a4954f0bcf38c90b78b5412c327cd941258f59004bd18d5" },
                { "el", "cf5e4c64f7e0e939f4b5d32c62ae83618471f45c9f7837c4b7debe8b191730a96cf23cad44bb30ffee40e8a6f6037a563a7a54e609d4e1b6dbee497daf0ef19d" },
                { "en-CA", "218887da9fa525a28dbcf41b4eff3904aff30620425848e8c2f86b5dfcf4494d658add5457532acb21552f600ef2d6801c6bef6e8d50b26451b587ac2df5dd91" },
                { "en-GB", "ca4c05652fb0ddffe01cbcebfe4942a6e86b4be390e59668bfb317267cbac919569975c18bc19d4c5b320fec3b8475173926bc19929237f54ffdbb026033b5c2" },
                { "en-US", "bf9bbd19f70b1636131b0dee21cbc26e5ea2d68171b6c378985670bccf10b50213f959aad52829d3db1f4d64ee6dcced9a5e9c502ff54448962b7e3d05313241" },
                { "eo", "3d5908e797bf48b69aa4b9c58d465a199a17a73f5a3c95c1359777ff286a77b741820f9f190ca03277f6a62a737d78906cacb1b254bca52821e53f7c71d7c5fa" },
                { "es-AR", "460c4eb7d3ec648ddd5e315289a74569e8be212904b9720f3552cd2cc1cc6c482aad568e2b15946a5007db47e11f25cda241d82966de1b0cb4426f84794beee1" },
                { "es-CL", "a755e4b2e987f324c6d9ceb187b78944205be1bea6f1afef0ebc1f886d845ed9b27853feb31d79b2574c2360ee82d29c82076f30e0c4396ed65639df68b8964e" },
                { "es-ES", "2b7193e1477b6bd84b51b8b4f005995ea4264e49dddf89abda71771f2b4b07c27e911b7321cfb72cdb9a7966338789d00059e1486f4c305a0ebe7514f3a12d40" },
                { "es-MX", "092393439fb869adc29bddaca5356d7ded3d4a4eb1ba1eda3378d3eb44bf5e2b3de33dae91c9627ec275a8b156e09b92129ba1345f3e5fcdc11c224764469689" },
                { "et", "16a7c6950dd3143a2253a96e903b62130c114b5bf9199019629ebda0bf2a384f411ec07bd8c9e8a5fdb32ccf494d1b86c3d19476a1c8868e34e6c0efe29e9d9c" },
                { "eu", "9a53e7a0ebf6b8e3f8e91d6a952ca78ec2c2d1f6af1a31a3b8ddff883655dc98b2124c53af85726c970f584b9c1b3013a358efbe2dbd1839255fae5f1ab96e66" },
                { "fa", "aa564fba7cf97b9cdc808417060ae640c50a57ef782a3d86feca04f96c85d0aa33afe05f92a887c2d17747f9600ddb98308bcac6d3a79d85e78c74296b2f6e61" },
                { "ff", "5ead8a79e6e967d17def5eae28f433b9ed4e0fc48447f157093ed44643b7c9f71a647fd53df1336e6d12f96fa6f458376a5bd68b8d8978159a806a047782daeb" },
                { "fi", "0c36d42d51952ecbff542a14a97132206cc8039dd8fd11efffe8f6f4883421937f707d580afd1b1f2c450ceb8a7d5e7ba3a3659f72a965edadabea0fadd99454" },
                { "fr", "429db1288449955ab3a4a3392083c5576286a91a82e37e98580264b2fef96522f4b3ebf7386fa6db575afe5c6e7058eeb35aaa641a7e0ac6a2c9817791062345" },
                { "fy-NL", "4cf5484649cdbc0b22d2d876b7747d7cd3f143099a0ce2bf91ddc71d40b06726011172c07018c6d1ee5ea3dcb54a034bb8486ebb8df1fa2341a11d4da177fd76" },
                { "ga-IE", "f3dfd0ff39a852af127ecbfe1f9e4bec32be2ee7b676c23b787118113a39d623f3618cd8e627f23ac9dd2fc3c8a3b99d5ab550efa08f9a2ef4db9e82b41cb183" },
                { "gd", "8ee4b63d82183451ee213ef8e6ed0e9b41a827d2f9a694eaf75d63a5df14d27a98e31b992210728ddcc28093892a0937f5d4f7b507232999f16629afef178863" },
                { "gl", "575b1c91087693fa055215452fb798eba0d071ea2052a8e0395c4cd601fc58f63f7a8e55a31d79b6e812aadf9764ccf56c524b6d1cd94ae95ceaa173f1940ae3" },
                { "gn", "8d47e23d6bf401a3f1e2f4ffb5a04cdafca70353e46b5a80e95e759f8407847cf0886da01e16c6a4196506c25f42d6da9ed62ffeecce139c29db75ba144daf7b" },
                { "gu-IN", "0afd05c966fa79d7f803d489ffd94f6e4cc25961a07ab020f4d844b0e82a6150938fd1ccb24530653652da3c9586d76e0821526d885a151122b8ef51e1dbbdf6" },
                { "he", "be2448d3bb83f9287036ae5e557bc4e379bb2c81ddff21abd3caaa84f2276824d56df49f440d5e694e7bf342f043d996cced858d2d1ec185a56bb0f5c144c03f" },
                { "hi-IN", "38335d6a8e72cba485854bbe81b6943d96dd9cb1b8ef34a40b643649e69dc356e039efcf4ff55def686c4dfae512c9694305f7d6cf1009470d63383e890b5dff" },
                { "hr", "ebbad7454083edd77e10fdaf6526fcdecc2c1790cb326c0c2aafd73a82b6449e61aaceb23ba90f81a083d6d9769d235d1dbed3b6dbe0ca0a72d8095b4485f846" },
                { "hsb", "04d6ae7cc74bbac9419b5621a5b82f103b1bca376d80a7aca1715ad9692d138bbd399f00766951b52d5509da54b942ad442c6bc39b734e5a5f2b4c8111fffdd9" },
                { "hu", "4f668d8d734581ad9c145323a3a8676a4e754a61bd0fae4f8cb7f81929c8153b811fea64f37ad84a4814993a40a64fc090cfc77d36e402db6d0850139dab5e5d" },
                { "hy-AM", "4be58c8582bd3f96002a798ff3e1621ae897a282873d09f69df015af220638ae4f83420fd1c6eae7174a7503f26cf877856172432b3f3a3f6559b87e2880ee05" },
                { "ia", "7f332c6843dd3a1b01fcd5bbb9d15e1b4b3e0994ae519a60826cfe843350c73d615c97f60cbb11bd95264daffdd6124258c10eaabd7c905f6188ea79ed5b2093" },
                { "id", "2b1f13ac20a4469bae30b982112dde17389bcbdfec56822b9aa7f59278ee3ec7f226c1d98620c63022d7c0324b5dbb39a2a97237538b4fa7833faafd8aca11da" },
                { "is", "6c976c637694a148ad7864b5a8e1dcb8daefc66cfab3a63bf1879d18aff27bfdde147b5f641470efee8b0d9f76304476757f97e5312eeb4d6b24a09ef9c9caa6" },
                { "it", "cb732b2499ed44871784da070cf4530a1ea7de7785d548faab6fdd0cd290aba522bf74856e216a0f4dc8d85c92a2ae6df3470b650baa7223c4ad59d779504f1a" },
                { "ja", "2482f55ae1886995773d4c0030b57a66694b926311b71df7fb879717798d970a30421ed1230c460a55f6a9a6296d3f8fcef994705b61936fc4ad77c369597914" },
                { "ka", "e73cd24c0cb9e1641d20d36c6e22afe668dcd4caba30f860366243f42aadb0557274b392656c711b8f79b5a5fa17315b0a9d539956902360a879d9eca8db48f6" },
                { "kab", "bd78d0f81e8817282efea94a581f50e304f7498d8f9012070e34ba999c9ad9a5ff6118993cff87f79b6a95cf619ec6a4e83d7f188f8c652ac87de8adf64a3df9" },
                { "kk", "ecc78183d1207e23b04edbda948c88411bac24cc98112548cdd037a0d381dfa1f6f1ed595b97de49c3d034fa13ee80054b4d1627d2d202c7ab9d8f47fae7a116" },
                { "km", "51c447066c88913fa6a5f5036ed009ffd0af7d10e7db236de0511bde3cf889d5c73bba46a27979b2e8f565c3968c90b9074ec7b787e851a51fcb0c1059306dbf" },
                { "kn", "7e235e57dd3c29ba073b17c08cf4e2ed6ff2c145a331178012f128ecd2bde4c8ec1846ee12768470683c63fa61e866318d10ed1910157d8769a02a2d518dd1c0" },
                { "ko", "e2b9fe68d41923b6592cc0687342ece65b41a1ee37742fb57be2344c3545da44d0b32305e36a31a8fce407cfc6727b4bf3c972c2cba8b8fc537120ccb5be3cdc" },
                { "lij", "859f3c8ff4173ddefd5e66cf68cae5558c71a96f6776b79e6b77b95447e2056735cd2d867a35c2b5ab13f5dca16ca99b61e2c7bbf0a17b4dfce83e3d7edc94f0" },
                { "lt", "df39349c27df0d6ea32de5fc3be0ce9884521939aa800901ebd7a8ea883da8bcd16fba684372563de4f5b765b5c445f6a096b087d7aceb4e77caf45b65cc0755" },
                { "lv", "bdd4db4e2ed3f340a8fe23261dea487c9ab2f72747db99045ce3d1f91deb224092ec4ead6faeab6ab1cc2b5fab777255f8dc93bdc3c2e67296ca0f27aa17143a" },
                { "mk", "a2b8b63e599627ff3045cf15090508954ce43693fb577f15413dd4473051b147d357c5d2f8b51876f5a5daf82219ed0ad35e1149c07913767213d1229b009c44" },
                { "mr", "00a85bfea4b0531e1b8974f6cea6a11c5459894f7bddd120093b127bc5f65bfe17ff2714b5d82aebc2b6ab6919eb82c299586723f685fc62eba11ab7bcbefc66" },
                { "ms", "46789bbf551c1569831eb05e9e6d02c3039c7fd31ece14deccfc49d7e7c98c00cad65088ff11864ebb960e828a7e28543cde236b7aa363782de8bcf25673b482" },
                { "my", "5f4d142d01fadeb3188c083805058306ac9b04f2f5e9196d32ff4e66b06c2ef39d53a0b57a27ba463f036270b4900ebf4054afd59340e5aed9c41acff0f02774" },
                { "nb-NO", "4916814ecd6b4b66b59e032c40177f32bdf816bf99d1d0bf6c253726b194925572636ba3faf08afc1f08fde64400e9ca44ff8dbfd4e1d58ab99074d01aa4e51a" },
                { "ne-NP", "43edfaa9330923b0cd6a6ef6858dcaba88ff6c45d0625c08c475fefee79366c13e0edba8b208d2f8071219bc622c58769aeb09d1bf7e766dc0027ee5e4713a55" },
                { "nl", "dc59abd802861c3873aa5d4e6b49e4af4aa8ca62735d447c523b4541b0f554e959c083937aa5d3ab7e58f854b1c8e9ea7833d288125e03de4f69f72f10e1b63e" },
                { "nn-NO", "0de333c4e9b101d202b8757f07c7d15b1d49fc9ea6f3f1c512bbcc6a228b704bc289adfc4f68d74246386757e800fa0956a9dd15864603625bf600af76fe91dd" },
                { "oc", "fa87962e7394ec03276e9b7dd7f7fa79b282c760a0db2da24c763c9033963f7df634dba77d7272d78f32d69c2b7c0f3c8696cd28b065ba819891a3baf404ae3e" },
                { "pa-IN", "2621fc088f5adb3352497e8aee1278f8bb306e65991fdd08575b798dfafdd8490ceac31a72d76ab6a9ae2c726046c7a91d910a80758d0c70b86e1ee38367e2ce" },
                { "pl", "6bd8dab5f751e0c79705d35c564f2ee4bc88165d6197bc04207972f5124e0d129549e37c4d633ffdbc079b91c423961ad0941b252b9e06f978e40c4d942e3995" },
                { "pt-BR", "fe0a6e8cc924c1f41bb4c4831ed59d768fee5715ef17586a03b97d492f439a48015e749b9b13a14e384f5320aa2de9fe7d42cb419a5ae17c82bbc814cb069abc" },
                { "pt-PT", "ad26c583145190273d4282828e65a6d7ecd376e24164f7590c3fad5a0e9c171ef9fe2a690318f7e6f3c2aba769867330dc826fbfeb0bd8adc05b39528182e01f" },
                { "rm", "e3560927033e74aaabdded3985211b5b3fe4cc1187e62bf99096167067e80d117fa512e3af6fc01a1750a7d0c1911f468f31209edb92e400c9b41480576ed6d9" },
                { "ro", "2774f8357ecd9e3647e88f2e3441566a5cf60b4bbc40faa4924da531d80d30fffb5c67d6966e15f83c5066cd662384039a4292ef96183cde0bd167a2bfb414a7" },
                { "ru", "e3bd53b030cf8c115efe100ee068276e20a19093087c2e407482faab28bd4e20461a0dc894385307f5e349a4fa864a4805205d2299634ba0e5cbf8e87840a338" },
                { "sco", "d29147080700ae859ee8ddec871b32941912892dc09baa7ed93f1158fe2a76e2e28ac4db40d6cf255236eaa1ef7e09756d09a44283d591621264c59a92f7906f" },
                { "si", "fd9b962765ff0280a0c55bf8f877548706553d2c1f472993f7bbc295b6bcc86540396d924c06f109e716e9346c6bf796fb2b4c54e6c0e83ba9533ec6140305ee" },
                { "sk", "be78de4e0b8cf125ea7aa98e396fe185a77ab78a45ad0d7345c2c25188e3c00a602e53e926ac08bf97b4250e918249e697de28ace6c8687cec4bfba491ae7c84" },
                { "sl", "49abb032b05ee4f3ed3466ea8cf191741daf51e1e323261dc15c442b5e9d7b53ccef00d07a82438a2c88312b320bb024c73bd6408e57cb8e2e19726cf249bc47" },
                { "son", "312928bf78da69965677e06954522b524802d5157a14bda51a2f643dbfe85c9fc74b0012a4c60e279745b57e566152729e04aaf52053ed5f396d6965b611b8c9" },
                { "sq", "82029f67ca7b14553c2d9ebae3d767059c18c4ce057f4405bb4043632372594bb3de2d946713aa1e8f3d749d90b284c8360d537192557471b7432e13fe063387" },
                { "sr", "8dc1e49bf30a811611787c6b74266c9f919fe784abf1fb11d6a771b6465ea7d64cc3e7952ff1ae7bbfa48bb2d81ba9dce0edf626f64c700294e2fd9559942902" },
                { "sv-SE", "c7cdd517b290d9f8336bb943fc7cf3845475553e397509650bc212512979d816498a95b4f7d74f819012df1af8726d15f6fa976312c5c872042dea32e0a55613" },
                { "szl", "d2670f23213bfc3a8d2beb6e75e72f95d019824fd5b454e6ecc89f57445ee89fd6a7b23caecc691f9d5dce0bbb817932cebf0181218e69c172d1f5d93b3c7631" },
                { "ta", "548d000d0d6f31fac4df0c5e4bd5f0bac8ea1891c2f341ea0839fd7204be16615f95277abcea230cebb59443884b0084b03da389ded9888af0c97dd1a5c6a973" },
                { "te", "8e83461f0e2727dbc1b010bc7e104b45ac9f7cd3f3005f6a5a1b7bf30969569af93f4b38ff5dd2525d2ddc0587462917d9157b4559e9e0f32fbe1dfb6863819f" },
                { "th", "4b34a0e0e8b077f69f55ee3bf18068e6537b95f5e9c820d0568c4e77f503ab4764097e6209800be530ddcf6d2bdbe6de84a70725e23030e11b760efe9cf41550" },
                { "tl", "78f8a78452abbc01bab5519f0d543b0246e2ef93fb259b35f2c154735a3d443b556b270d2623fb9908e696c21ce0e58f781557de38d373df9b252cf3a071f066" },
                { "tr", "efa5f0b8d31bca360bc39347acbc1c2778b6703d7d38fe201de37d23c3702659c10e424bca001d81e2b4377787992b5a9515812bbe9c89f6e867d13687a69ed9" },
                { "trs", "ca222fd83b4ac759a896afeb4b0ee97b88e402948cab055c6b4245990107d560c3e0b1bffcb7a32cf5c8e9ff7ee135d10517209ddd0db1a33a498f6078359795" },
                { "uk", "7e95f7c46161907fbe1e3e735660806ad182cf688eb110a389de179949917db6004440b5395994bc0fa493a3ca8050eca35be3eef3429e9dacfd6f36f924c6fa" },
                { "ur", "1116bc57bee0118fb67eb11fc91d3ad6d2094296a82be9a1e85a278d058c5f5d5c034f030528a4a63b1c0700d7c7d3b529a8cafa7986dbecf856efd00bf75b06" },
                { "uz", "3cc1bd920724cdb82a12d6e878e10a0c03640635964c457ba2df72230b3e4a3614136559b7f2a1667472552a08fc25fa739ea408c222a7c4d4448c35229d4ffe" },
                { "vi", "f53b92beb076689bb031b10d11593635e5158a93f3cf2ca1385b618c99113ce91b9bb998b768f9c4295fd46f1ce97b00bb0a30974b537911d52c6210ad886105" },
                { "xh", "291b5bbb73bda1028c6ad6fda415b577ed9ac9d437cb22d36106ea15a209fa3ce00081a66744211db13a2252f84b385bb005a71e1db705612c92337bf76a53c0" },
                { "zh-CN", "7b7af12f045b2a56872df7720549b6860ada50d09ca86231d6daf6e49a3e0d463eed0d1b23f2bd2b257fff1518a0f0c6c6723efca06db7f3d8b9e076cadb584e" },
                { "zh-TW", "eed8e99775f2030fdde02c22247d469504787eac3521a0990813fad0119ea82c306b298c635d189222ac9f1cd27326011b2a9b65118151dbbb9557cf20fe196f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.3.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "c8abacec30382b0fa08a2fa69811c4cd3fbb21a6ee1901337ab584e0736397c06a7474b3e9acede1827abd5a4140e8b8e9269ca8dd393dbcf650aa97afbf5d53" },
                { "af", "ad4b9bb130e7c784a772ff2394e928d20595e5b7ccdddfce7cb88fd6e18be9d7db01f114de901562de394c5fa96576fbb34e105f11ffaf79dc82b4af0900fddd" },
                { "an", "54c0400c36f8ddcea2fd56fa496c29a137b92a427fed3940744926b529d1bce7458cfdab539211e478237eabe5f9f1294069e27bf83d6f42b103a6b95fa9640a" },
                { "ar", "3738b7ed740883d58caedc02be4e91b85665969111f4398d1ea7549f8c2dac962941fd29f739294502cc208bb647eadd5abafc9d83dc48880437e4a71eef633e" },
                { "ast", "30a5f1b4e5e6c6368c1e844145ff4e855a9ce4906bbfad4c95d56adcf6d84b7887a39509196f05dbeb3da13ce478346ec3577da9ee05ed2cdf2f24dca0ebaf10" },
                { "az", "71fdb0a940fb2cd716a1053f35f569574d2cf96405f3defa10b81ebf1daaeaf361fc10f349e4dd6c2de0229fbf9d93b986825900b2019a062d258f7adda03759" },
                { "be", "09521d73ca91c686095bf71519d791611d4f8d4cb2d300dc1ebe6ddea32771641fff94a697204e7a9c325b8da0970069ccfe2ceafebd5cb6e5c2114ad4070217" },
                { "bg", "67d5026cd184d63ce7257756b5071bebe59bf24e18041c23a65dd5214f1c0e195004ba4adba0cbd75416916c93c26885f76ffebd1871751daf576a205cab29d4" },
                { "bn", "c2ef519d62d0570e41d4d41176064e477d79c5321a940daef9d487a940bfd2ce32a384bca9166476a9d788075e1dabe70cf993c467e49ee1c095a5818735d6de" },
                { "br", "c8d4c9c62cc01b13ef2a86b3f19f5aeb4f631026b51692a10bc76efc2971f6a00c5c1ae4d98d08c5ad14d28cb1ac5d55d27b9df1bba85af0ab5759a640f4d705" },
                { "bs", "031b72ab46f55ace4739b038f1c3a735548d5a0baca97ba9a4c95a9e96555c1f8b764b2407504103be6d451d1e04775d0356f16105d42e35fef571f7da2aee69" },
                { "ca", "37221ed74334378dc0a64825ca5f44e41aa54e0f9fd59188bbc6d7321cada095a97396097a09058d1b9a92f08826320fac9bf954bb1bf08ebd9323017de11f15" },
                { "cak", "926ef48c330ebb6f8f95bd060dedebc4f1c4c9e424686e6fed5210201fe368b6f53762dcc1cf85ece0dc41b41e4d8b6a6aab8f0eb095b907991336c6577b53bc" },
                { "cs", "c1dc977c64d9d09101fbab627c5f0d6cfb664215c404ea2f345def2337fe8554ccf740093d8acce25733d9ba054f3eccfaaeb89d8aea5766ed20406a68fc2019" },
                { "cy", "f29e982fee0199918f2600d2857e1a2592e59eb05d8144d4de1aba22f9b8f32fc97fc3dd466e1e1754dce3f224cb23ff2068a0c0871432891657d7fc479b8266" },
                { "da", "c73cc26cb7277b85cae727c8be122ace8ae702c1633ccf3dc3526e8b6f238404d5e11f14aefcbf6b68b435ed71881158f22bad27f0624325cc81e43abbf139df" },
                { "de", "960c9a32b875cf74d58d03b37650595a3b6ae083b124667c85e363ec4c0179ec92d6dd918553be4312598c34662efa6a7d25d418e0f5f29004c0800712304c0a" },
                { "dsb", "5277d9aa20f3cea0bd347831af75d4490529bebe4b770cf35733324993c016661ac51564eac40cc675bc3b1f62cb8a82bf5b3a9f3087f01d1868927793c050a3" },
                { "el", "c9dbdbd8776f62fae4c596eb17b8569838b7b47677af9afb013903217ab714939a7ea9941b3463d7cd4bfc72a4fdab2a0ce2d8f1e7e7e82239eab9cb000a6027" },
                { "en-CA", "d980a0cd889f8a7a27b9bf46b09ac6bf3ee34fbab866a673f15c502778ceffbffbc60f5942673d3c00794d1e8782fd473e5aaceaec4a068394d1e0b262882854" },
                { "en-GB", "94031da68d6dabd90c0de0e11325441844c0b9faff8c1a1bad78a4b3443711d26b8a0f8f9da17a98beadd64e883599ac990ce3aaacbd2a092d6aab0382b6b88e" },
                { "en-US", "2f0c384f29da921ec8330dc0ee851e0bccf07ba1888a9b9af890bafa45ff5207a9eab0e246d7212b4a0fa2564c93a08b2796bb26d1121fe2f13fa7d0ed3a4f7c" },
                { "eo", "ce2fc5a9ac488b0223d11e9b75b075c4454a6593a23d005ed7157d928be62c0e26a0ef56d177502aeae4a97415aa3962ef8e855bf0c98ecbffb9118ea337e4c6" },
                { "es-AR", "340ba6544205d75510912e937cea22a5b910d61f9b0ac0105b65f0282c3ac70577e37ed206b3850af229562d551db5d03cd9c9664739a8440e7c56d3dbcbfebe" },
                { "es-CL", "a9e32a0770de8c28840359e0a2e9073f619cd422a0a5884abfb4c4c2a7506878c223209db934dd536beec7d76bd90b81946326c4e4ee92a07e5bfb69b6ac8bfb" },
                { "es-ES", "632b0e1a4ac7dc519cc4e1573ed1a053e4ae8b0d947e49298534f9d0113c47f7f2d55cbc79c206db74ea555548d633e883fba4b5fd07a3e2ef80ff7f23771ca2" },
                { "es-MX", "6e6d7ebeb53831bb948aa714008ba66ee5299a43ebd2449b20b0d5b27c432e519a92acb1624ad9a18b32b743b3b3b9a96639f26e9ba678aa6347a86a15fd6a66" },
                { "et", "a7e148a8fb1c9c8337c381d2e0bdcd077bb62eac36ea3652f30cf561ebae68cd6ef7b132360e486dab7f94096a45793e02950f164b99ad23f772e1561a2a6351" },
                { "eu", "a2224f0e0a5697e82986c7f3c8c9ca8c42678782a4ea278cd608a6452f652ac5e1e80b56b6cc3e990e999371045c352c7e7fa6c9dd3ff4c7695c1eb2ae589a6d" },
                { "fa", "576f76867cd0f75918365dbff0327ec0020ac19b42c3b7df5c34294f95f42e82e101b2d2ede443d0800d0a53d112acffaf0917277a05851e6ce62830b8cb720f" },
                { "ff", "73eeebcbd3f72f131978f389d6979a80264e06f3589f418b6feb8682d11ff0bb29b68c5cee6634471d4321e7e21290b2e64a942ce334e3c6d69a12147bfa6121" },
                { "fi", "be8f96e4238b891bf877490120bb0401ee4834a295ff782444cf98556e1a1d8fef62314612988dcdcab147dc488779d9e2dc5a1fe5035a2eda3fa94557da7a2f" },
                { "fr", "2af391b73584c568d11c749d009898b154be278a9377e18beb9092dc17f8e783a04eb2f9669b85604d3a195eb937de50b91575d6879c7d542978b9a039d9326e" },
                { "fy-NL", "baf3e73298354c1a74e49d56dec1eb907d312004444c2041df8b2481eeb3acc728b65ac1c69fbcc140f964dee4511a68890e1eaa49456def258f7071461fe148" },
                { "ga-IE", "713133b86adf07788305be7d971fe1227817f7416826884423c8d04c17012bb1a5813116fed21274c8db61d991a74bf8bc5a69814b87675043c7e6d12d09c842" },
                { "gd", "ad8d6c8c5041eff8907843fd0303c6a69c239a809fdc8b8158a1c44dd28727fd7e6bb7313430ceb8709420577715cf6bfddd6f3ec5b3ceb1a08bd7bf7d327b76" },
                { "gl", "69882975e28051b85ce57d5f478edabc0174dcd9461994bff20f2d00fce20ba3675c48feb76806955b360a36b7ceca91a92d5dfe1f60a4f132928e9571ed5afe" },
                { "gn", "09726c861ec46a09879fe1587beb5a850cf26e96db97ccd5baab884787a335fca957efb75ea42aa9d434dea6921715fed304952fefc0bec9c21edec2029370b0" },
                { "gu-IN", "100421220b3a36a0a6664aa571721d0a2b8bdae72d346510971d3675cd75ffbd1f20af1ef3e752b4c579f98ce9292e79de30a9c36cfa46ac00381fb83f429ae1" },
                { "he", "c74054acd94aa53209b44eb66deaa6a0945c0781de0530cebc5c28143b1020351c9c4b74bb2adfc1a4608c66be40322ec4e1b45c60b067ff9c04d3fe269c8733" },
                { "hi-IN", "e31dfd6ee56b267fa07995c31271fa5ca9b32e2c4106a972db00df8a5fa602f90ede73c29cb3b68219710017edb5905c84596a26082f0413ee68296baf380a2d" },
                { "hr", "ebe05e22d7975ad5c317cbc984d29c131e3246e9fcfb79302c392fad72a72243adc5c73d9851fb07c2eec2fdad05937412df995ef69f3115084e855fe39b5941" },
                { "hsb", "2da05090e9a77e3aada38869371599a00aa1ebacdc63451b57279599da61d959daeafc471ea05931fee85b26634248271e04eb2dcfce6cdc3592a9685a395c60" },
                { "hu", "cf2149a4679d8dcc36129262a4b287354dd9d68d988225fccf0f6da04d57c317abd4dfd9dc68cd14fa19067cce80bcb44f84e101d0d2b2adc0825ac26cb77598" },
                { "hy-AM", "3fd121fdf703e911573cd9c694008eb929977b76b5ab4bf1ee57cc4901b3d9831f866a86620e57ea950b825cdb26206a6b120e077d6a77e7706fc952d00b17f8" },
                { "ia", "47a8e294410fa6fcdc63acf17882756c1c08e8e9a0952ea1e10852d68aef889bbf12bcf9eb3a4035669d940d48ea819abc646e2609d83f5ab111b600580f671d" },
                { "id", "68a083a18dfafee55281943586a29f5c473d7e276434d8ceb7820e60d0de7c2f932e7a34abe577890dc38469bd233cd1b3da263565f13d54ee74f024163e8d8a" },
                { "is", "c241e5bddddb1852fdc34c37a374a3b5cc7334d8b70b9db48093b05ce4fbc57617f53e9d9a638b8c39a25bbd27d9d6c2aaa51fe017acc9ac7c1b9e68330f0e54" },
                { "it", "d4fa24f554e3e2247491dfcd5d9b9a2398933fad3dd0fd4b1385714f32da872f24d20c80b72e9daf00eed3d9f56da5760d539504547cfb1d3c9d44c5dd6b86e0" },
                { "ja", "bdb315ba1e0df6445fd70fb174e0880a8e19cb446675354c61d19cb9f2ce9df2eabf826de221cbe047067cdba73c71e465dc28ae3c0e37eda11584339a2262a7" },
                { "ka", "8a20dbd9c451e9ee580a13d11dca815fcf8a4349a863d8e5a29c916eead42371c3f62d4a1b03f08424fed3fa7ab7763e3fb50579926fbc37c6f233d889552760" },
                { "kab", "63ac8e7e4a5030158b43292834e1a29aabe809079b5981db2eb7af2c0b4e6ad286a2ff46b307fce97374ec04a3132f8d015366005e6dd279a5c46e62b7c59227" },
                { "kk", "dd3a9a0b5eabfef52853b6d4cdaa48236c14faee75ce2d9479fac9ea0f388046d4183473eef8ad808dafa4df9f594914f22b61a4ca45e7fa37c06fa9006fcd80" },
                { "km", "eafbd08d6381212df29c47336fd213d3dc77fce33be5534dfb8311d3c3e33b30d3db6ab50595a6258b53e7fea8fb401a126487e83a8b92f38681b06890b7c08c" },
                { "kn", "d65dc24b478ad13c9d2af91e52501747cf2fcbc4221f73c2632c46008b51399c95fbf7b55bfa0d0370c542061d8a186e42115b43bc13f89e8085347ba7e3e306" },
                { "ko", "1b5744f1e3a51ae99580d8ec8f87f960766d3d327a58cc0caa1339b56cbb56abe24ac277fdab6984997925be15106c1b9202cc0227daebec62f52e1f3f124d2c" },
                { "lij", "9bad5a96307b35a0dedf266808d610b481bab2b19453371a460bcdac96fc1783812518277c17014e682967ec1f68ac964a0353d18f7597da3306b82203a0e07f" },
                { "lt", "41239e4b9a5069fcca242f38f9b2a4b0d24f18339b2ddeddc39bf8f0ee00b7de4568c4e2c36c59f2e2433bcf18b2582e29fada903f55df3fe63bdb1f92efb618" },
                { "lv", "e44fa5c6a6b9f1abf2eb84967edb0506252c3e8bff048e6f5a7283806bd90b98efeb200022d4a403a8f66be6e0b9a8bc76f24a46d39f699f64a702a9ccd5feda" },
                { "mk", "627fd30060912a3f224b3a22ec62bb216843aed29334a0804047b1ba707f8b5106e173021b1b1ed81d2eb0ddf6502173e8c61366a4612dd1e790d20f1fb5e9dc" },
                { "mr", "87598185b8b3b87fba4e97e02ff224996f30fd73db3d40c65f3fc53dce00a9563034a02d266a54f636d0052b236e0ffbcbc7c9f9f26233ff67f92be816a128b6" },
                { "ms", "b6972a64cd67802ede9095f61f9c5aba4abb36590d24e336cc54d5a51ef370d45a69d586dd5beb88c6016585c73f5e8a28e03c4c405aa1c650c2aa0e65356354" },
                { "my", "7b8c1e052836f5960ab1662e570dda5d62ff359bf5c66e2fa608326a6239f7b2695b895afaa012a9fad8a234f675b94d11de0be9c8738420dc023339a1affcd3" },
                { "nb-NO", "809366695d30f25582ec7643b36ba0479074689413f1c53997eebc4ffbf763ca237086c894cc7f064a777e66d516510c761edcc0155f3da5d4fceac070dbf6eb" },
                { "ne-NP", "512cd5027953cae6cb1e08585058eccebc64df1a07b016ef7479b37106745313b0592e260638677bf127b52906aa9af405cba97d37751f8644c212af52c48e79" },
                { "nl", "30b0949ba3c1336077058bf5d9398b1c08d8abcb6e473c477ec34eae73d753c634e52f6822b6dc49c7544c4da586ded1a0fe2b82020783ba96a0c83a2a8af7d2" },
                { "nn-NO", "23ebe2b7e97a5c4d48f14fb7323d364da864827957fc9adf78134016bda54b2c8751237c302d4105929e7b02a005aae8c7aa7cbd3e66c4e8f3bda500b76ee1ae" },
                { "oc", "bce1b6cae07fa134218b51bcc49ff22bf0fd6fdd346188a23bfffbaf774b14f49af1ed3f2acf6d8e75a3b86b66ea73d159c765dbe6dd3e71d5f58242611de3de" },
                { "pa-IN", "3d55c9aba6d6e83ad8edd2b19bae5c7ffdc3752cfd78530704571b7764814c00abd1d25fb124f361f17dc0a36a5792f675595e6d2536014840719ffcf4d10619" },
                { "pl", "a892066a8e534cf9ec6ac36e9413cba5b827a0ae11e4a945ad2a729d5adb5624a746b16d9cbf17a5d572b15e4c01cc05fefdeb152ef1397b73a7202583078c16" },
                { "pt-BR", "5da77e0c81c7848d6e4d7bde35346b823d5738ca2ef262c1dd99c79cca2013ce49f2dc0cbb6ce9efe803c0291ad5d6bb57429ca5e9750bc20931f97cb1659be4" },
                { "pt-PT", "a16b3ebf3d9a86cbc9c39efb05225c6060fce5a0a8f68ae82246ecfc4a9f0f01e3ce023bde7e7afb08cdc2e464bcee38868b034ee40d3d4bc65afd47cc0a7ef2" },
                { "rm", "d008a8ee94514b127d3cb6fe2b443bc41b15e9bf1977b983953a0874cdfe23d4c2046d99c8c8328692e231034616692812384baa407cc42d3d0da3cb0981fc78" },
                { "ro", "4d56b705b0fb4df52d6e73f1ec397bc0602c40f2910231c751af3f136e8ff300af152b8e5e460fc538950161372d948c9d9cba35234a7c29cc1778d0a8ee6498" },
                { "ru", "905c041615c507f2d760ac87a736541569b282e6c73e86a2c5115f9b91472ebe7451c9d76556c3e1992f7a3af7ae5ab7dc6545cc7b01f8be87e8036f4b5cdaf9" },
                { "sco", "4cd626374af5e802db886089fd7dac18a2fb5528d8811e7ce967259402266709fbfdfc0c7dfbdae21e712a9de58c3bc0b0b57be8b99597899786cef6ed1c449d" },
                { "si", "f0b8146b6ec7d42dc1dbf77f9fdaaa4f282668e17d68e869669f5cd10ca3f7d0b930f0f1539d02f8c8f8fae275dc42806cd1246bbb6c1d950ff904b9cba9ba08" },
                { "sk", "5b35dccf6ac7908b0900973003ca88e3f791dbea6f5be2d9e783889c2e9831cc580cf6139d149b47aaf744db94ba4fa68f507895f5d8a936408c7469978fd3dc" },
                { "sl", "40be02ed8558cb04f7f2f123dd5d0a9e27e0c9490a783c8018f3b4d5455752ef1b6d229b8375e302c4a3e26187c46b4fcc4cc8f1d6ac2e42696807f15a34165d" },
                { "son", "46c543379a900b73135d7c7552b604e983b2faad6a9f510f0e4a16e194802cc10425f924cf0da26e2e3945f68a69a01c81e3177ab43c8d45d087574cc24aef14" },
                { "sq", "552cd83a710f80742d7c079c715b556384cf35c9735ad7befec8d3431b340c378e1b659fb6928e03c10fef615f33b0802f70a76a986c4e36c7edd0b465f27f59" },
                { "sr", "60654c7e2b34f8f072a6510f22b161ab4dd3bcf11ab1c5bb1b97ca651c8d19c0ba71c5f3104991f63ed854be06bfa9c077ecd26bb5cf953e5c4e5c11cecbcc47" },
                { "sv-SE", "d160963d0d6ad120a7313bf98e0eba8a475bccdcfc3805aa922d6b55c1b4d4ec442b87713ff42c90512a0c6b3a64ba34cea65a203de90a1ca90b4d1708df2315" },
                { "szl", "fb77593bcb50cbc1180aba7a5db2aabc18d43fd5125d31fe796ff8354afb842fa2dc3ca46e93e097479d2b6be9c0af7a9db416a68a0d289f9f330129c85b06a6" },
                { "ta", "c77da9db8f0f48906411d9893adb176e3654bd4ec5965129bd41d164e42727f0240c05d1d61ec0df123984ec04c3a3e235be3eee97165c37f58228a5e85d2e5d" },
                { "te", "3b0f9773466121ab3ea4fbf6758e18680fd54d272379583e0e54208cea9c7d01857bf2d3386119a110620c29bb98f669346e2de233dba226b5b91332b551410d" },
                { "th", "8c1bf78fcac3391d176f9f215331c1bd701441c90c55f7d4c93859bf179d79fa44023133363ed5168e1c926cfbdaffa91f6728279cfefd2210ec62c0a9aa704c" },
                { "tl", "51f1991ce04d16dc1d5b259d903e0bd4a19c35e048143983ff3df2f016ee4220d252543902f371bdbc93ff6f450c2bb1fd7a26b8fc3a1318cc591bbb8977fc99" },
                { "tr", "2beea9e3f04b0567f7144819b806e5a13abe66c4b6c77cb74e89e708ef9d4c9b5d5a81ae016e7294c1e1272513b76d0df45bb5e8037634e93707c1851d4abc1f" },
                { "trs", "b0d61a292480193034881149785a386854ee7e0695850fe58012afdd10145e895b071b2dab790b792423d96389c77e1cfb9ff06e0acfb52db4b3725be2da649f" },
                { "uk", "537e188ab9ce0cc40daf7ee9b69d345091879107731ba69c58e22a228dde415db20b725a9eabd8c432c40fb15235fb2f45ab387d443ec9cc12800618d9efd8ef" },
                { "ur", "9546513183975bfeea2e34e53d47c2b71dcf675f1fa0b02800940617134dca22f14f1f5fe3f1f0d665508647c688d4239e2fda634a204859c8bed3af4a2c9716" },
                { "uz", "d3a5beef339916f9a09a74a3e6670bc54943e498efb3437d923546653fb4f9e5f5cba288a812477a2feaa8dc813fedbdb372eb8f935a0474aeb14c2d84fa6cae" },
                { "vi", "7809ac62070cd7dc9829448b8b6717583997cf2fbde1046de8c99fa0806f4cd73a2c32a2a4ab5f67fa7b04b3818000fe740475200d82962506d8a02770471838" },
                { "xh", "4ef0e63dd1f792a1a3a1662e6a140857e43bca2e2553cb878794e972efdebade3704a47f0e5d29f83f9be788c244269f8fb8c8801872ba1932632ce70d3a68fb" },
                { "zh-CN", "8bbab8f45e4b67b75bf3fc6d9d4ead5c1dedce481969a558a41f065ff8cf122e479de25720ff8dccc2fa67f97817789fd8d0704c88cf30b552776678b48948db" },
                { "zh-TW", "e96278aea1df79e710b8d9cb4439195d71ddeb6b5b1a49d2e561052bc704500c03f578d235609f3442329c3d46e4ddfb182b0d26f871dae169559c69670d3dc1" }
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
            const string knownVersion = "91.3.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
