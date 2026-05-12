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
            // https://ftp.mozilla.org/pub/firefox/releases/150.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "2f5113cb108747ae2decc040598368d7f2004c6b60cb9dc959595aacb2f5cbd424de6b34917f82a3b0e07a7ad14ac6f6365c20d3021f7b32ed07c83525604f1f" },
                { "af", "81801e0d31706abb273695a96a81993280ef38e0aed6a4028840e3da11204a22a628d8b25e58a2042cd24a0aaf37431049672cd2abf383d2582dd7b39e31f63f" },
                { "an", "095180868f8336d8920d1be67ee8047767ff946ca8c9ab6f11acdc2f16fadf36e640188e1c7c40fdc84e415234ffe2ff3c60e917cc1df5c97f98886d662e338b" },
                { "ar", "ea6479edf1e755b2f97776af7ad9f61becfef14a3a11433f0174133def1586396ca2d8ad21987bc301df203599300137329cb26afabf880ad014b4642477b18a" },
                { "ast", "260d4e9d397d029d2c3e32af60e8fe81c2dae98818f187c93e13808796418a69b8f5cf5bd7d297d66cb8799ad8e6559325d6ce5a806bd92657ad8927b76b89a5" },
                { "az", "50282fece8134471d6e70dfb7382be0ee52c560f161d2ec36a0c6c52d628a8d8bbfba6dee92262a5d33976a5c6bc8d0d24b53693c6c1be77eba9d1dc63c4713e" },
                { "be", "543896b8a20b548c699625e4e559e366e0f25a4b668d5de7801947022276029f4b68d09a45fc41106378c9d200763071099993ec2f93cb4a0bf205ac94bf6c1a" },
                { "bg", "c73e5a962045c85199b7a60d5e1aa1def53f2acac68f87edf1c3d1427ebcad224e486ef55e311e91c89417305be04d212b33f085336364ac765db7648c84842b" },
                { "bn", "1dfa838c456c97bc369286ea5ddba210be14e864c6e8f7dc87e657886565ad4914da6ebe62b5447ed47c4e0bc69e246ef58ec62d6e9a19fa66857efe4a669ad3" },
                { "br", "d034617cd8265adcc7193af4c004ac94b400c5b74c8d3e32f789f8ea996bab9a68bcf9bfe4779b47bb1510a9c94b63696bd414fa48e126b782c6c2fa36ea3abb" },
                { "bs", "b3faf884502044e9bdbb68dac573b1549b84ac330f0c18c08386e37afc0fd40414d8c0f20356b609c810718b6253c53dfd1d2dacfc0779bbdec3110ccd87c018" },
                { "ca", "0574344ebc26c0516c4f86d6007b2306365794f9a97697cdd507481ef7b927fc8223d8c3d6dd735a640edeee2845709edfdab0b0a8d27c3279e10ed166bd5958" },
                { "cak", "2ac26ce5a340d3ae228143ab42d5fb48543ffa019a70f6ebd6012741416aa84b67ea56242bc68f342cf119fc8d357e7c11e194d06948b1e86d76e7ac465d2e92" },
                { "cs", "ced3940f79a34bf89b4ddcf8bef30666bb30049f9e571cb057c353241de3b604dfb94be09306487ec7259c61c9c8ea38c1d565b8e7ce948b3c3bf9221b3a23f9" },
                { "cy", "69b6187dd8dc032b73c4f53afa2509ed22a5a34d86c6e2bbc14b4bd6224206c1d1ba56141ff316f23b6e518a7609be203ccda297a0778b3b9997e35bd48ccac1" },
                { "da", "264dcf3c5d5c8f2d6ea630a47199cd6fe3ee015568575aea4dcdacef80a76b9099b1bc836ee6d8e69fbac3fd3011e50ac1ce4c0a0ef863e78666261f9c9984c9" },
                { "de", "f9bd0d109a2099eae614d30182233d111bbcb381587f9f5c730cf024f6b18259c8dced5844251ad8cc7b6691eb30fe94976d1abf240bedac4819ed24fbe41d37" },
                { "dsb", "a6dc6d8a81e7353b602b3b0e83515c9b29ab91d332baa016378091193a6740495c8432c5ae5857ae5eaa018a00303e06b8f9bd4393bf318ea9d2f24f64f23b3a" },
                { "el", "51d6eef20f0940009fb9e05d5b006124239762285ef757344c46d3257b9e6f120c7f5fc9be5b29e028c396ac50cf5a4f3487d6667bdcc077fc36373c34e98443" },
                { "en-CA", "1aa1ccb63d06c09818aeace38957d356976cd284f0fa894efb03c6a94f1f99427d7f298f8a429178d3ae6d4b58a46bc41053083110fbfb9541217fd443f6bb3b" },
                { "en-GB", "4c7ad2bd9fbc0bb63de927ee94b9f58e6b22f4f4989043c2866b5876277ce93edce2cc6572f7ab910c0b7cd3ceeab35b6f2d9cef94333c2dce5bc61d6fa875fe" },
                { "en-US", "10f63d6a1102a7357cf73aa1876ad4fd13531979113c1137ad68463ab18fe7c943dd9616b145eb90ff5dd5b119090de0bf91b5f41a3518bfda71875be5053a77" },
                { "eo", "2e69e854650f2a6d40d3612a18040b21e13f414819627f5674a22bce34a8f46848da53b5d3be0d18c3a6c5437746a04a6da8d825a7a496553830dccf8b5bf14a" },
                { "es-AR", "fd48a5864bda79d9348023d7776983054cce636204b3147c6d2d2d74e88285c8c8f8adfe8a29c5b05f4fe31163d28ca27e689ffb53cabfce5815ebd4660c36df" },
                { "es-CL", "dc5a6abb23ff1da0291fdfb61d5c105988328208d49b49c6be3c20c5e64e067e1b824111bb95a93856c4cb2c5084fa643c425ab21d52d5f967bab52ce1060b2e" },
                { "es-ES", "a8323ce6e25d168d268ead4619189259199a52576110dce0cbfb6db2b1228c901e59efb3f2d9b15a6d908bbfaf33bd008aede11d568722cbf218e173c880f044" },
                { "es-MX", "acb1b67e46bc2c6e314b6b7d9a30aa40c5097a5d16618e05dabde71a4a1bc53a9545dcbcd78170a05621b0c1f46ed25c62e59adf4f90789fbd70abe0b4449c80" },
                { "et", "6ac0f84d89322d0e8d7346d687b54854f0fd152ecc4895905fcccf59c516b99e494c3da41261d6258ad6ef0837330b0f48b239875c3cefa468434c33a008867e" },
                { "eu", "4b23a61aaeb00ff6fb066b0a4a1971379890a4f2135f8a6ccc9161d49580577dcdadd22b40a7e34df084e875b3b23e02f716ed319b5f0a5af133ceb7aa1e11a1" },
                { "fa", "857bba8b71494918930b5222ff0c13378e47bc1d4d4789b127ae9434f829619907a728bf1a0098cea50d2bf8f9c36c4fa1b2075a43393f928548432a5fe0ffc8" },
                { "ff", "8181755d9c4e06db950d3585cf14638688e6699b6090629bc678f886208855aab0217b9a20660764278d77132225f93c8cf249b88da9359033cb23c7439004ce" },
                { "fi", "d88d48c032fe8b0703af92e78fa28ab8338e5ab770d8125621820ae2f505df0a8ea449c41f83393a1f5e4853de89a8f0d445fbc4df4b7c66c61a9d03f9b40fe2" },
                { "fr", "642f5851315c520875c4cde5f086cc159252f06fc0f20205439d1da2c5b0656c9b29bd44b26ba7e33230864601f9e765be5a75aa7faebf3d449e919584a08a85" },
                { "fur", "b845c957f512b6ca7b1316c08fc10e1c6a29f6e5eec335eb23fdf0cb229eb206d8c230335a5afd68459e58a1fec517215cec27a72f568d86fbd84c70b351415e" },
                { "fy-NL", "0917aad3eb226cd947d6dc112ea8a9829c173d4561b448e3fa3f2c1dc81840b14cac4ad82b352e85147b1577d6f12162b953969e2de229d2b64fa92b88427ad8" },
                { "ga-IE", "9d701d63fa8bbe7cd9b0794d966e5dd93198ff289574293471b2df2ccb3ce6f144792888df13d0a668129b7f33c8cc15988013f8d3dc2d55177e5f2c9a674d3b" },
                { "gd", "877a355093b792d47bfba805333ada446cc7b8dd13acf61d22c9d48bba45cb0e888e6115a1ed6cc13b961cd56e23ce3b8211d42f13adc3fdd3eb11e3d443e1c3" },
                { "gl", "e189beea904379dfad9913ae8d87b47636682755aa2a6b48322d3113ea6140c8e9b84b5034349020bf161a51126201aa7b27ee048f06bc99f9a5bef0eb960fee" },
                { "gn", "d1da0a23ec5c057a3a061ea516b5a7d1f4f0568a2edbbe0f86a7e083c44f494cdff6e8053e7b1a182898188011f43acc8ab61500ce41f671c0580059722f59d5" },
                { "gu-IN", "ea7f67d4ae46521863ae2ffdd839237502662fe7fadbfaacc426de010c4b4fda608fdecd91c2e190e54ff25b93723afce61237d67f643fac4924f643f25afff6" },
                { "he", "e8674fdfa7a0436cae8adef64d6ece80f8c5dde22d34aa4cf6ead268cf5f4675c8124f6115ead31c0b7ee5590a9ecb6adf0d52e1c70de8312b6f22ab1cd1059d" },
                { "hi-IN", "910e9f2c92e2b104a82ca785111eb529c13cb04d1350314556d775eeed84c51846c08d64a4b727d886537f7c175c7aee472c0a26f2cbd86b9ea1c09fe791af52" },
                { "hr", "ad370aa41067817deceaa0227febd983700bcdc0bf58d921b23abc6d78620c77b5b4b0f4707b9da5eea3c675ecdfbc1c7be05cdb7f2a39510de88d6759ebe507" },
                { "hsb", "7c1d5c9cc2f9fd954ced53c798ae329a2470b17decab5ff13c574d5f4a81def1b6c8dae38e42f5d0c858e5ef9ae9ba7a5c7e345895d34b4420016b07050e5ddf" },
                { "hu", "bf5eeadd7f13c628551776c316e18fdb250b53bc3b955d1b672054bc325740dd28fc71f31eacde28fe4f20bfb6e1f19443aa951f93945c2123d7f644e73650b1" },
                { "hy-AM", "6430116282ddd3c45c9e323b3410278acd0db52f1fb585c8f02163c304f27356127a2a83041c35bd46968a58abe887d63c78c45120864f983b51ab556c612c18" },
                { "ia", "da0f76459224525e5c5347208fe0c9b50cb7cf0e6044fa1ae93cb8d1c0350ea7e19b88b2ff6f5b2a626d8d9ff455b75dc0d85ed5e7a0439b4a00f65302aa2386" },
                { "id", "a3eca6b06738999e5957142affd86d27a62c3ab252c9249b1e3bcf17113f4a705750cdb3fb8d33853c4949a302169d5b0f90ca6d879156e145b969718d0ec12c" },
                { "is", "98077a3cc480e4741d83d66a0a154cdbb4f946ac67832ca17aebf301061c05fd166fe18907deeb642790ef12b0afb770b0d342ba8ce87199182c00061b9435f5" },
                { "it", "6200fa301be959c5f6fdba86af488b8074177199ce92d24aaf6c69bc9bb4e6e67663790662cc2539ca7beb5a07af7293a20a995cf03f0071caef73346400776d" },
                { "ja", "40e2ad6dd8512d71aae6886ad4a9396258496a622e61ebe97be2f0ceb3e3d014b11a36efbd1a1192f808dc1d14ce2673bf8ee37617bb84850a458b6d1e9a2467" },
                { "ka", "b45ee4c1c5700e01b6136179f68de740f0c780bc152cdf07171a65e4c06302f1377b0e45c1efdf4065a016010a4a40fadc9d5c0c563595729482dfe1fd548ce3" },
                { "kab", "86646a1d268dee0998a05a9862a090c6b024a7c9bdfb8580bbe8b4aecbe3f9832e62b3ce5752644e6e993c2b0dc2f5cb7f40150cf78ee01177b36936169a30e1" },
                { "kk", "2c77492fb0507639824b11062143fa325694e143a1fab56996992e846520f8cd7951b13528f06443b6173c2ca133eafc211a00ba16ac2fa8c4a8750e59d7588b" },
                { "km", "7da291584f939a66bb3a447ca48ab3997a7f283c0b59e78fe100e6bb180c5b931ea31aa252439d81e190e5c864fb18735c741737f28d646336ccbfb71c0cc16e" },
                { "kn", "3778e0c4259aa31e42df49010210a651c36a9a0e22691bead3c8ff55488d15bee61a340c12167f5ec5f47e69eb24cecb03c4c8371eb04f85ef5a1c80fc299536" },
                { "ko", "08fe01312f551f82ba4aa33272ab6824851b3b76b7ae8886ee1b75ae722f1ac3afce3db82bdbc603aa08a89010f5797bd094abaea31a1f4e8e9040099948e9d7" },
                { "lij", "c13035050e5262d4a5526081847eef9c6e2b2b57ec50ea66fd8ebfe7fff3240d2afad00b59739043ddd588ff64701f88ddfda9972e63123d33796bec1680a641" },
                { "lt", "ac24e266ff831beb87cf3b6d5bd906a2e35378dac6035b4320a0bb83bf42de5128c17789a2568a819bb0a15f3a17b782f528e54a538a487a1d7a5fcd50ccf677" },
                { "lv", "f49a2fb691ef76df4e0dee61d399ec5a35d491b55ba2426a241d7655b34c6172dc2ff01f1ea35536f6580171dc9e96d687cf2e4f870a86c06fdbee2775e2a9f9" },
                { "mk", "b6204b3a0aad0907a744b283083feb0405330fa02cfd7018c10120e9088fb761c24f672db7001a89e20e06ad3b8faa14e267fc201c406b32abf61e8c77868d1d" },
                { "mr", "22ba97d9a7bb43f74c44c7d12fe1d1dde248e30ae149fd928358d56536718595bc7dfa3b739fa95ded7502c2357afc4a81ec6c86c2610411399effe160b524bd" },
                { "ms", "259b4f9a374746d25ab8f0ac960542cd5a8bbdd4a88e1d42828a36b4399878ba827a1f9677f5ae0a16e7af0fc4857225b6f76c5ab0434209d82df8d676d6da14" },
                { "my", "0b1b755d91ee2fb0e370a53f322a431b45aae3646c457cb5547326fb01d7e7873788b6abe274f6125bb26d6d093ce1176c92281e13bf14cb7edef931c19e0c6d" },
                { "nb-NO", "33b831761f9d7a72191c2b4dfcd9e07fd305f79c7d4181aa8648f4c847e879c173589527e4f58f978dee90c87a1b3a97a076d4471672e8b256ff1c87af185425" },
                { "ne-NP", "ac034bc7bc024d4159c96aab3beec1282ba4df21b2ec7455a6677bc52120afcab7560d973c3f89031d7422df0f56ab3e43a1e6b1864d0a6b1409042d9e97e936" },
                { "nl", "4e9b82e5444b470a551e7f17768094b0f446f0e9e0caa13df8c0ebc45f64ff827ed9e7d6e7f3bc09f93a138c46abb6c4690b1b55c9ea475196faf0800408fc90" },
                { "nn-NO", "74a71feca3f6ac5dfc17087c31b422047d0b7c91bd33efbd608da0a6c30f5ba9ac656572e2da903721f199b79225e19304f214fb6687bacc1712869e38130efb" },
                { "oc", "026eccb673f6ba90462d7dc61466af30885d8467b609bf23169b7b17beb4c14a5b4190b15fb6e8c54e7d7bc2fe85640168fce6347a4a16599759f46adc044b82" },
                { "pa-IN", "a6297e2df4f199c95ad7afb7b7e310ae15b0c11183a022d89fe5e71ec1d464b2c6bc4b4ed691f5d9949b585819bf92daa32ba44bde981ab4ae96cab464433acb" },
                { "pl", "539d8e47a5a1f0c7b9d355c2523a395603f342a5b3f79edba035501d71ac1084c515490b25546a333083cffc9dcb8c2e31cb3b9828bacec52309c8b51d2d9bc3" },
                { "pt-BR", "b9477692c18f8f29d96f48fb83219ad3b65f4db80fdd9b913ca847becc90229dccc911aa7b7efa355f0f62737aa88a6d0eca292a048c744ae50b11b1c32124b8" },
                { "pt-PT", "74dd92fdbde2d38effa858bdce8d8b6cc06243012b1041b6a0fbe3c4578bb0dfe7f49e5e1e307943eef397e7d0c1e3a0e2613a446fd91218bfa939361331c55d" },
                { "rm", "dd558fc03beaadb277b9df31387d2308ea2c58a202cd318ec7c7f600bf43644484bcd8e4ba42d8db484817c03880bd43178be6070ef8c48b6ecc84e93f6cade9" },
                { "ro", "3d3196f5f78afc90fd1aebb56aea1e290ddb32fbad17085c9561ae85d6f71822de971110b5e6426ab459f46eb3c007b7dad1dcd6de4e1ec2491e5713e64843e2" },
                { "ru", "931b40adad814752ee6f694413f2023bb37631dd67c757a0abcd81ef34ec921de09a332a2bf50a55f911b471ab4413fd06a910d09b33298944627bec4a680714" },
                { "sat", "876bfb499481e99cd1bb339920cbc7dcfca2495800037c7dcc939d76a22c15ccc580f62ac731a516f7954ecd58410514d0c377832064bf8c5c5066caf97fdb31" },
                { "sc", "f11eb7d2b22b5ff4bf3ce85dea3a1b9e21028715bc7edc579fe0ca6683501b7bca0017218adb2ef737d8961d33df4aba52a3b2d3d25ac44215808c3ca4bc0023" },
                { "sco", "74c01b5e12f80a4e3f8461b9393a2c9658a2e43a887db4e7c7a67d7c5cac2783df77316ae8e4d0c4b4e2053380da90e85db92b956f838262e3c50fed0a895bf7" },
                { "si", "6e3be309a1044ff6ed2ff33ff9edb3d9d72d40932ccbfc9786b329d47852a54ee410bfea7ad585e0e8c7472842fc56cee7149fa05c92057fa264c5e27a76836f" },
                { "sk", "1ac181bb52ee1072dbd8c24e62ee956374ef910c8fa01f59865f24864a1729a05716646e1b25495f7dfb77a4f7e6576306443f162b7aba8ae4231bcd7c7b830a" },
                { "skr", "3ceab51e51dd8b3c37dd25b45fc7f31098849ed3db72bb85345f92ecc86ed0c7bb1863891455739c7a9cf127e8766f86e7042b0618fd809ffba186307fd67e28" },
                { "sl", "243f1153abeeecf2b6b28b9505b7c83259096df8e2bf08e81eb28c7381378d3584406fbc73e3df49cf37b8d79cb65f9cc404ffaed12510fd4133cbdac0824173" },
                { "son", "6cf9f3c7297bd769e0c4cdaf8f9800ea4575193e9df9e3b35eb1a95b66f2eb6c207f14a1df6daed0588553b0a630779374d09f670dbb081c78912aecf9042e94" },
                { "sq", "cb5b7c9e8e99a26da373dc22769a06239e94b9a14830b3db0212511b552c11cd2b64dc09fd0ff83b0c010b32a7910ebf549f996c88d19b5bc57ff1d18a2879f2" },
                { "sr", "79bae90073a8547bd24373886d8ee2052c60070c600b841db853397d05213d7b8f6068102ab05bf8997be1ca9e0f67ec13ecdf99b786c07af77174532bc10936" },
                { "sv-SE", "cb2216f5b709876414208cad8b76087014c7d872da1b815bb7096b8f7c71d858d649ab02c6b5e031ae3a0f63f0a7eec61ce391627860bf24a9a04faa698925c7" },
                { "szl", "a41b4c48039f3d3cfa722aa9c35cc501f5ee7e48dba2b2f6dc1837ac42117a234dd2179f80f90c109b3b76755a1e625f1bb4a03a19f90f8d4672136b60645eb7" },
                { "ta", "a91f89833fe733a2cd9a83e1974a157f1ee5f3665f72c41769d8422aa99e79f1c1633742d1a87776069e6d64f8b920a432ba2bc87ae6e37b6dd654122c9508bb" },
                { "te", "ded10b50d8f41ee8f69c09e08f68a9c072c05f949568c352ef6c4b7d139b215b25ffb5d94cbec408d441379707b908f38c071b8b50f8df069245a18447a0f5a1" },
                { "tg", "9fec23cfa22954fb89c11b198986aa1054a22b127d117f5691101c13550389ffe880721019e6d150aa7a3b6cb4df004bc6774de4a18ed80937f76b665eb8b900" },
                { "th", "e46d485dd8bd70b80dd911f893d8f91fbd3e55f29370d54f2e2b0199e48b1d82310ecc0f3e9b0c2a33e7447552fd94a3cb77cf3dc7f78e9539aff07b58951256" },
                { "tl", "32edecfb1dca6907194d7df344bc6c206d4d69557ca83e3eadcbfb99efef024f180cbefa82177dfebbf013c7a02fd8e4ebede02de8985e0910bc4abdfd5f296b" },
                { "tr", "d09f7ddcb693537cd90844c91ebf5c27c9afedae2dd6060f47352c169286bd2958c7efdb5e8897396bc287f97eff83cc04bc703cae3b99c00196daa4f1d65960" },
                { "trs", "19073b688d774228369bd26cb96fa8158360feaa7127388edaefc68be41a4672b9c58ed48a081714dedb54b10ac6f4902c2c338aa9838445e77a8da77f8f42a9" },
                { "uk", "f26ef5ac8c467a83093318bd440f8a2bd803aa37362fa670dae340c0638b9dc7b85aa2923af8cc0480f0bd3f650dee24a38c37a7e9294d47765ad7603a0fb771" },
                { "ur", "c2ee7a3deea68a58aac026487c1778d03f1de4a5e5f4fc4b2c7bfc24b4b39f374bc15e33ea444da4b97d7a61f1e5a136b44933fa762116e520f0b41c7e3cbac6" },
                { "uz", "8f567401cd1c6b08aef568cc3150fe34a6615d1ab93d3dfe74d47779f4c594e9cccbe397e8a40bde65226aa532c6adc28e8acaca9008ad0cf2a1f16e756287e6" },
                { "vi", "aae93ca573934c32f293b6b4470d76c9631edc842926bbb9a5ba9ebb7bc7a50e13fa8c40d3ef149f62e865252026ce56149e926fc6c86d88a331ff1edc29e4ee" },
                { "xh", "acc3acad626d9641681d6d967b7b9bcc899d2de6678050ab5b425f6927d4bbba97696db3a48585edf44bcdac9bbd06b24b8865f87997feef8483200bd72ee407" },
                { "zh-CN", "009833b7876d1e97b99fd0157f9c59bb837883efdc49e78218c20ef87e388dae9d8815677530262724a18081dabae475172493a8d7a59c3fbd6b61fdf619da81" },
                { "zh-TW", "baab3dc1422cf9229a9a682d5b58028a9b6f0fe83796ee6c9472f7220995e4363aa9c9cb2a3aaca6ed52ed3f6ff9251bc1ce6f76e2d2af7331e092597146fd5d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/150.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "1ea19d0f78978312e39394e7bd436734a078f942222568348d6adaab2af3ddefc1194eae8c7278baa8fd9ca0e782fad72b584a609c3c95b8100eccddd0b5288e" },
                { "af", "9b00e2e4ed35046f9ccd01a12cc2da0175391b572030b01a645ba3582b937e14d489029838fc2d254a316ac427f9f0864dab76e68e8085722fd8ee90051fd965" },
                { "an", "b3e6d79d0d84e38cc9f5cdf0d03ffb18205e53c906af22e236f07cee6c0620793f4f78ef145c6eeae2879bd787addc7551fd25bb3a4c67b956234a421e430192" },
                { "ar", "df876ea829ecdbf2bfd7e7b2c6388cde059152204223bd47779c3b5bdff029e932d70073ca6c675a2fe6d2a8ffd19643532f026191ebd08708a127340dd6d9b3" },
                { "ast", "e84d0143135aff14fbb7ca6f23e08a252e69fac7177207d2bf884f17cbf0c11fcc43682d81cf716c9c784d2ea5f416954c0d983227bc5fcbbac058cdf4552360" },
                { "az", "3db9e509a3363864dc1e3d2022ace405b3988faa89d74b8a4fda461a870187cf13650cd1f58b163333e306fb2e05cf55ea8928d59e965437076fe2eceb3e155f" },
                { "be", "33336922ce3680299305fcf5359a90621921ed52147e0957800897de8fee5440a7f2b1b36e27e7e43b884b16986680eade6d85ec77ee431414ffa07cba40e63d" },
                { "bg", "957b8488a7fc0bdac81b6467f5d8563a8ae7f18ac076562a10c743273f3f9fb6815c93412293b2cd9f099afb23c9cde70b8ac1994b39de80fe2291fe6fbf1d04" },
                { "bn", "8dabd0baec2d8500d2f49933c7015a34ab89572dafc856bf8090dbc6b716448ff87c97e506ca609f98392884338570672cda1c04e672f774efeb487c47b5361b" },
                { "br", "ec913f246d64d4a2e9601ae6d5cf38a28e47f629716f36b4dc60daf0951f49737c333ddf9fdba17245cc4b8a2fc568ba821f585cb779983003cbcb3efd36c0ed" },
                { "bs", "022f5701021bd2bf6b4c435320d13cc0e618acb407957ebe63660c06d76110240c7dd668c05f8c3622943e30edbdca60363bd54ed514ea3eb3af95cdfdecb78d" },
                { "ca", "c1543a1e2cd4b5472a7def3add05a3bdd87a71484c47b93ba286a4c7ecaf841916cd7ab7cb5fd0d6890e432de12453a7e4702383096ea3f33ae186eeb3f08959" },
                { "cak", "001d4c0164bc46bb19f50d9ee711a1c01be2d094b7d3deb121ca32f63f5cc8db1d1bdc3a9cd5403b4d158cb58727b8bbb38c5443ca65f30d185185a06314a48e" },
                { "cs", "b3c1efe08f8fcaa9a83fac812ce24668eca97e1219f63a17892bd693f453dc90e9471cef0fff7044f8cbfca7b87f92f188733ea1ac5684ac85543aa6baab9759" },
                { "cy", "eb612feb8f169805c7158cafb6b17a9c6854d41d65744a3e3055f47ff68f4e174115612d39ebe50de47b7922fa6162f09d3d3ff6aae7a6bf99b055f8ef0f001c" },
                { "da", "98586ee3c4ec44f26cd28fcea60f9b43b9b1713c0eb7098b2f63c0a3aecf0e8733b17318790ec001f1a5a569b1b2af24bb8b4c6ab9ae021832f5445af011e6ac" },
                { "de", "66ddc4e2c3990d5d8a7e24b8ca22537cd4976acc9d71685163eeb58cb90a9ca99ca3c9b0dc46b63fa4a7efcec50f6ddbb25a48769066b44be810b2e72ddca768" },
                { "dsb", "ea9bc382d03c02984ddecd93cecba8e2589f28cb916fcd5a9317f2864e97a6727d24eaf69378d68852d0567b9f157369ddcb134f0be877619cd69965ce6af81d" },
                { "el", "b2dc542289de2cd0716d2e1b687dfef43209aeedac044240d8daaea229711fd3231b29da8436bafd601acdda00e9749c9eed6c837b3948903fe82087569f297e" },
                { "en-CA", "e3402d986b0b8dd5c312382bbb1739fbe03c5c4bd37c2eef41c15aca07c0ceab56d91b6c4e66cd4db63167bf355229564f4fa5205bd705173c9aad2c3a3504a1" },
                { "en-GB", "18e3d64af499c629b8f41446bb0b007408b3ef5a4d9f365aa7fa388de5edc4cd0c2d26fa2788343ae279d8cc7622c93c05d275504744a1cf7cb20a0355cbf8b1" },
                { "en-US", "a30d05410fe5acb6e91e2c380312f3414e731545c73f981ad2dd57f838101132d38295771ea410d28f337fb4caa019d07e3eb771e44400031465450b45ecbaa1" },
                { "eo", "82c09304ea1685dcb6b69ab1ee4222cc04c8d288308c8dab21d6365ba465d9c872856200ddfedfa962bc3adfc13b92805ca29b932cf66f64c7efb1237fea4ee3" },
                { "es-AR", "5d3cee67b33262141c07846e12fb74f454e035c33ce70eae1cc19075b2b7e25fdb9ad26c432651b7a05792e0a9aa95532442628a91ca870c788bc14bea600f42" },
                { "es-CL", "70038bab20decec2da3897668d78f9c34f3f82216ebef43b44b11a82211a5f3800df0d68b59d7ce18ec01b58af764310a570b37e5a75869874e92ca5b25104db" },
                { "es-ES", "bc28275c28ff5abb9c3aee478940cc8dcb665831807aba15fea0929f5f2e1267744c89fb1c9c9039ce95c6565b79169f4b0f97986bb27cd250364241c70c87c7" },
                { "es-MX", "7e05af55974b244f4e63bb8d086d64c5ab1d5e0b6c190f993b814ad14fd8b9e83b12ac0fc5da2a7dfab7c67d6167520e7005312563f0b1bd6c92b5e9e4632b67" },
                { "et", "d438cb64aa9db7464177c6d4867256a71082d6add88538a5937e2846e07107922e907974e51115f3e679c4fa15e5f7f7eaa26b2411cd1da031eef8e8a287a6a4" },
                { "eu", "765b8adbf85802591f588f55cdb8b3f6ec4dd986787f51b1979e1f772839185ecef4d1ccea7f96ed515e195fd34d5fe5dff387f603a2753c40a689ad8e4928d9" },
                { "fa", "4b9d8fd18e1d3367dd64367fb9231f0ceceda11dbaad57223826307d9603be24984166a3b4a2940d371d8069521848e0a39e18e65d556e4b35590c4121bf94b8" },
                { "ff", "608f94cfc1bf42d14a8317f35a2276272e55349c6f79fb49c75800cd6ff2ab004f5e4d5f1081de05a7d326fb96eebb4d2fb94b4181ae27926cc14909e5b33697" },
                { "fi", "0f5c43199b33966e5c9b716400d2aaff013240f37db8050a4c4dc10546e34e8fb7f379c6f5cd71c28798fcfe35d9f15d9fa4f457018b069286ad2f18c3c37a47" },
                { "fr", "e6dc22ce399b734174e3c69b75e18b0456722be8fcccf875b8b58e8fa481e511c1d5ccf41a3663d0c17f6c15cfa21c5726c6315f9d12934aa4d9f6a5d320c096" },
                { "fur", "8ee333fc5fac0718946e434b66eee363f55ca8b213a11b21f478511b431c5246f020ae706c2a76605db5b27582e73cbf7428f44a77b5f7d3eb8cae3549b53d60" },
                { "fy-NL", "523ebf97b0362b458973c40d8e0a0f686cd011b6313597f7186049eb181989085f83710cbcafe43181a34eaba65f4dc5f712d78fa29e208e53b3ea1f4b56e820" },
                { "ga-IE", "c16a664bb95d601e8223d943bbc71ec391d7aa24d55266cc539dfdce4f3507c14f8c46d02d15c77737e8bd9075760b3c7c7201703142064f265eb4a2739bd515" },
                { "gd", "08ff42f5fd43e7a9ed98592ebc71bd5629617377e3cb4f9b569f26b8dbd51c72a17c8baf928de5a6d09876a46d7351ce908064d9853086af0f833dc6e9b3baf3" },
                { "gl", "768a5d418f5e035cc27c2b63a3d0dd6b9a80410c27984351a5a05791e478f88d8dc0f8b8cfce525ac6e94353766aa7ad4e87ff7a6380b1e9491f397f482a3b58" },
                { "gn", "39e222d48c6cc3023d499d8226eac7fea21c3b35896668ef3d2b09cbd5a3611944c9571eb2c48937a3f3cb9a15fe1df2f98b66aee46b8a147adb72d242c84dd1" },
                { "gu-IN", "73666f49f80b1b21594c804911c76fa752b431a5888a1446c97f89e9f58c2f42d5a539962127c2cfa00ea3ac78d6d3bd1266b83b9afea0476b46a6ff675b90fc" },
                { "he", "0faf29bf95d91a376b72b4bc6b4c0428eaad2bee7cb33e53981cbac3fbcd2c1b5defbbe0beddc25c8806bb5cd868a97866e2a6cd0ceeab2349b9001b88cc3771" },
                { "hi-IN", "171b82016f699a45bcdae6f6e3cd8e466f331f2163876b6d325c227fa3e0677c79493ebd70ccbd1a84bf2b21e479c7caaeff06943754faa946ac9faf00a88492" },
                { "hr", "9d6fd3a0ed05dfd36b4323b949fbf1d8bd739dfbc0d3fe641f6d0d352edf40a76aaf2c130581e54b7453eaa2f802fc7b4df55faaf321ee230e368e9b1e30e76c" },
                { "hsb", "ba1b5f3ed516fe2d70a6732ea1aee549e1f3a6781748ef59fc929a8f43b46255b0f860f93a4730db7c0a2722d516b4f90eb82f5d892639a151ef6f4b83606d77" },
                { "hu", "16bc4a9ba4d07e0e39f5c8cea4bd161beac75644d1ec88a0a206b62645cb9725e25ecce21264f46fff24914fca946dc5c0a5a6a20f867a148cdeeab2e5d27b45" },
                { "hy-AM", "db2c1161fc81ab8d3d2a5ded06e8dadcdfd9bb3986fdfb03328eee6dd6cd6beca39086ff2a62ce167024ae2863d0319709dd28740e85ca7339826d7fe6bf20d7" },
                { "ia", "d6b44f70fe05724bd511b6663420d051e4765af1fca2e396031c0b854b9390fc5b4786bcd0403e015d3305ae46e85ff3923471d136187f4080b7bc023613aacf" },
                { "id", "4a75a13805d44a8df52f8a1685f3e094c76a6ba2e3e602caf477672cf8ac9803e0d5882a35b5cb0ff8077bd8658d2f493f85d33c696d0b133b3b3911b61becf3" },
                { "is", "55d28cf20d690418a6e4fc766d4663e956051e36d98a75fe2be1cc46a5e72396f724dab229ef5182f5f48beefa99dbd95d5073ac37e65fcde193718e4b9fa322" },
                { "it", "ea24d992c8b687e3a79916d03e699f9951ecb00bff94d4546730c10a172d745bfd538a60bca1f8fefd0d9e6c1bbc103456b62e1c03980b5368c27021cc6ffd2c" },
                { "ja", "d5604f897c50653ef928b5d7af10ecb69f085eb352f33ae45546bf2608a6b9ac1e9c60dcd51f70b6fd70032b7409ea4add67a08ca2d13b71f9828f907c97c6c8" },
                { "ka", "d5faa5f239747bad944c8536cd5b75031637e56dc67ab20b374602a6835afcac6cb809df6898aafa086d4a4c46f22b6639df5faf7ba69519afa3be012b80500d" },
                { "kab", "9ff417abf5cb8af3e77a83a00e8ada99a87328e4e085a4bfb5ded15d67f5b1bd16769c74973ba82a9df6eeab2c537bc188bd6d5a250e89fe4103b9b9432bb8a4" },
                { "kk", "ce64cacf84ba149e1333b3d19941ef4486e4b94f3d003b839690e3f2d3cbdc400e4b93b3a13caed7e6facb726ed40ea38d664ee1b67e1ca9afe2e41a372acaa6" },
                { "km", "f437806528118e85f33834f7a61e65969950eebaeb33dcfa0e8242c9c613a5394e6b878f7c0fa4a75832fabbb3d476fac4e63eca6223be9ebf89e1f37e968d61" },
                { "kn", "798763767abdfb21ec58ce2f140e729ed7bf8adaf7f61592fdb38404ffc4f39e1d427c57aa5a25d00fd623c9798866cac589859e3c6d5b35f3f8cbf208f98c2b" },
                { "ko", "a88bb7fb3a7e50f7c702f69da1b5ee829f6aafc709cb20656b7501e6cc07752fbcc43f3ada0a2eef0b8c118adc8db12c6620cd1eb5373af56bc8cdaacff49ee9" },
                { "lij", "eeb95bc294cc2fac37e1eddda908896192873a05cfc9ddaca207948593951d8823fbb0f76bb34b37ec5898451ff95b1f255808c7c86423333c75433f08862078" },
                { "lt", "60a96336b640941ab70592b937b7f208f8f590615fe087da5e5d47118206862605a1388e788d0467bea9cef0d6edf3df4e09a58e9d04b5c96c4e3e2f7f42a029" },
                { "lv", "832cfc7f6b50989877b76ed6aa0d6d4f646b780947538f74ef71bc0bda83f4653a7557760db6d3e7cc3393ce14b59c42c5c5f51b55c38f5999afb68d16cdf7eb" },
                { "mk", "c26508e0ce41e4f84bcc5d139a6810def33e073bf27b44fb4833b0c930ae42dfb0a377ac3de26d4395e787a5416a33b34ae10d35a3885f6df4aef66c38221533" },
                { "mr", "ea4ea6b0ac0c003b9b45e1195d01f34478635af7b4e90bbe51936957ff3a2f2a8b98b9c9d5fc378e27be2bee6b47cb9321ea8b499db2768075d07f1aa4783620" },
                { "ms", "c33ee53bff217bede0c2a9fcb3b79517bc2545b368b971eaab256144eae03fee449c04ce989732fabb4ccf5af5d07fe76bc3505be426b3531bd7606067f3ed8b" },
                { "my", "50e0124b7c29df0fb1b72c9ea5dde77e33cce96029f00fa8139baf133a906c4b7c2b7250550816bf46b9f3ce76bf7eb523e1f8d8c3f727f83d44e7844dd286f5" },
                { "nb-NO", "1f0b4b6b636fc741bae6614f3ce1d336b5d512df847b600f6cb63a4ac7ba543dfdc0ea96c11ba5d1e4b3cd2f774f39af55e96ed937c7fed097bcb3176864a1c9" },
                { "ne-NP", "c4e78f72a286c909cd0d5bd10ea733ba33ae4419679cf7c58f3c4eaeec3fa615c0e45cab193cf63517e21ea0b01042a7f698b590223ce6957a849f987e49dd40" },
                { "nl", "aeb25c307a2728f1862747cf2d39c064bad26494b47290118c99ec49014a770f6af1e82ef61e853931146abe13597b27deddca20bb53e4825512870e37bd2635" },
                { "nn-NO", "3e76a6a910fd26e54ce7cb9f5a946e7a7b7e9c4934429604064f1a7c519f2c5af5e4c3c416a5d606863500b3ab36170294791700da5fe6fa2d0964db1de50603" },
                { "oc", "224358cee258dcddcd38393eb9ae25832273f04460442f24c053fbbe87d288f0f8e66b74dad822f04d47ed914ecaa6897ffafe76ae452bc9ace42d770cfd8031" },
                { "pa-IN", "72571cfc91e2445ae68edb76175f3e75166394324a4f32e1ab1c26fd63e8a78834aab3b6433f590fe93607f570c72c721aaaf0fad4ddad0071992d0b65d7b0d8" },
                { "pl", "2032901cc57bee7fb192dd15bb07314ca03e18d762a3907ce6faa1debfaf9720b939d2f7660fdf099d5f67a66cc3db281affde9f21cd1d85ede578d22e7cba2f" },
                { "pt-BR", "0056e16f08124f14a47e57df80c334b01f3aacd194d609c976457497c3245bd2a6703a7bd828b9025cd21492fc6ac9076ebd2412a94193f589947d30366c0b54" },
                { "pt-PT", "207a55a79c6b3531e92f61946f0994d6a6c9eaedf26b7919d4e262646bf728d15d07efa04456ba7e205f611d1a61b48678596560e790a396d3845e3cacf4d828" },
                { "rm", "650a10130742fe6bb3c94aa08c69fc9ff0c56397ed4fa9ef0a846d1e12f644815f899f793551b108e2910a3d5fa2e33bf0c8cedcc55fe3d26a9e9be34a7a1851" },
                { "ro", "1a7a643f66afb03d5ca37caa8e83b72ab67a942e5aa651abb562ab82ee80c3f3a7e9919e26208fdc63b3182e13e081af07b26e8064d642c54256c5bd1686c5ab" },
                { "ru", "fd705323d30626b059bfd10af1cd847265f487baf82c12d550d8c25988fd0695067e8747aa55dcc51b7283a3dd06381293423d358e8c0b6b61ffb5c19e4849b3" },
                { "sat", "e39da0db158e2637884a0043fdde2ea2b2448b40dc309bc192237317efaccdf9f0903adb9d5370423b173b3437e2624f0b75aa66e463dbc85f9e96918257da32" },
                { "sc", "715923c242b73ece2b18023ef4b132bf49bbd76c44f3844e6f43147fead50ddedea8e929f4b8c68474eb607e47ab9dd46d4e2e003dd3c94c4847e8822b0c081b" },
                { "sco", "e411ccaaeb63c42568bde7127e4777af1888af4e6d4fe7222d017db197b0afef0a6ee4b4972b10459aae0fb98c55992a071f7da29c153f6096dfbf663a529a66" },
                { "si", "e6abff97948f65d9e2ad1e9d202f29e23b2c9e29b82087a611a6eadbcc0c27048f921ed4b0dc5f65abf023ae8c4b7a5dec158e34a4745039f85612c5de2db59a" },
                { "sk", "ee296feb514bdfdc1c0c0533a1ef737d0b6af5122cc34ad428c0f4f33ca1f64979d8fd46bd72541e4d1d8b0646dc7169de9260daba238fe4700716cbde9d2fb7" },
                { "skr", "0159715aad5ebad26542536f5a56a6b99509d96e9d667210c4ece6c2e0666d63bccb26ef2491a6e21d1b4e651c0f1d11d9b1d1385be7aa08028b826179e9bdac" },
                { "sl", "1e18ce41d1758eefd491601136c15f52085711cd74e22322ce80b152d3491640a12828cd6600aa552e125a5bfbc899f802d1a7bc797402db5a61c45be2b3af9d" },
                { "son", "484dd80b9a8f38d49da354b4f3020360aafb2b0ed2e6c9a48de82da8d3460ff7c35ea902f3ee3bd216fe0503dee99da53979a5cf1f52856489502bf21a67250c" },
                { "sq", "1c8cfa9cae4ab8afbf763ff7b594119230ed567bd457a37a138c95f215cf8cf453ed41df60b5320b3ca1a860877c8f5a068409c4715ae29202aaa29ac590e5d1" },
                { "sr", "052a02a5a3d33e2b99d15b55f697d244dce9c9a3221030daa383c6eec14e361d22e3e94fd77d0f44b1d40f840ed6db1c9c250d69ef7e9fd46a22061d3f4edfff" },
                { "sv-SE", "a005ebbc1b3912eb9e32893ee24c2d5c25e7ee86d3f2e848d3402ab7a41667de834cc25bb1f25d50ad3a3d46b2dafc85bb9c04db7fa8dfa9d02833f017998972" },
                { "szl", "de2be582bdbfa09b8934812fbf6cbf939bda0d6757cb0f9f9547bfb4a1c6ce6a9bc534582b60dcfea5bc6de026944259a1d7266daa29a2530fb5fb82f51ff81d" },
                { "ta", "8e89a4fa45845b52e9bf5288824580aeae089f1aa8092f6f01c99fd6d3a0e2615967f2390667b01de9a39c3fb918fd8a483a5052e3d38f730fec5fecbbab305d" },
                { "te", "041deedfa15bd928a4f6adf30766c71370df8189638d6d3f4d4b59eb683dd167f49e8559a7535468a99ace6f9af958d146349295956a1a7879fac30df6d0a610" },
                { "tg", "641fa05401a51cb51fea800a4f3de9ca87abd4b59ef9460ddca1ad2165e4b59f71d4ad37a6ee03549195ebfe24f3253076c78a3014693714bd76b8273842388e" },
                { "th", "a3b5e22481dc0e383eda329e10f37c449511a7c7364523d3b3b8bbfad3d47cd4f5bb0e043d0fbb0aa7812d133b0c897320ae403e6338bcf20633b5a202d434ca" },
                { "tl", "3a1302a60df41baf2c7f2dec63ce49e1465e87421c0936abc9f185130259798ba5c0eea2416c87b45cbe385d95f6ace8c7fd2eb2390fabc7df70b9c3759fd3a9" },
                { "tr", "9786b226f87c1600c36b006ffa46ea5e2646df21f1fbf2f8d1b538eaa32c673e2765fe4e95c31f58d606298f06c1da294d168cb8dbcc4f2270f63d6b0a8d1345" },
                { "trs", "d541dcc9a9785a19d9f4087e2c83bfb09f166106ee9c301437a1df6603b67686b289d7ae7621ca18f1cd83cd838ede025f3b69fcc5ee6773380794716ee5cab1" },
                { "uk", "5c2acd58c6604ea8381496de5f4fde72d48fd25aea6d030192c936a12583fcfb3d5a2614080309f0738df41e6b203d5aaed0ff3efc487757eef12449fcf774cd" },
                { "ur", "8e0b65087905ad3e9767803376dcbeac88f2c0e2e80971756ab9f090b6abf723ae1360355321f21ec4b3dcf1927e3f1b3deaae41ab3c30b78ba1901f3ecdc654" },
                { "uz", "02ccffbd046d702bdb052de4c3ba414e53e3d70c3b05ad83b05a5cf1207983cc13e4b2fdc92ac250ecc1ab2dc883c3e86d7d7f8fc38c9cc65bd9b437747ac533" },
                { "vi", "9cbe889516097b24e4e43cb05e55dce667cb702d3864298600fa79b5f5b083d7afa0769af2b2bcbf27e0dadb11287dc8a98eccb456eac98c1437ddc845df4eb8" },
                { "xh", "5431e6c68a460af05b8c875e1328b97d0e0f429f2b7d6efe0d1f89e6b3417036082a56ad338d0f3ad1405b3a5bb06c7f02dc3f1b30d5c7234d972e7a21bcc4ff" },
                { "zh-CN", "53d7a6bb6e6351eca1c851f8101a7e641d8105df0d3bd82a638a239abf56e5935bdb39a37ccc2bc25e0da3180d89c90e81c275f6eeea62c250324805a2944fde" },
                { "zh-TW", "98d5afdc30b67ac6dcff54aea5f5b35580ed7c503900089e9a3851001c413c2156bc81fb5283f08240fc4b1c98948a0bd54d84a127b3f4ca84d90920db5258fb" }
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
            const string knownVersion = "150.0.3";
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
