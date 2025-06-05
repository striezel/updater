﻿/*
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
        private const string currentVersion = "140.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "17d860cd3c25f1138841aa92cf358c63262d8dfad7bc0bfafba8f010950efd37dd7e8c798d3fadf661cc5a98de7460e2b745748fc5fe21876ec3011425bbd6e5" },
                { "af", "42f4828b558529148b126cb1acdbf116d4ed3c9e60e4b999249aa655347a8e103c0e7c3fe5b66db0ddd33741a255add4d3a106c63b8963ba686dea45a885989e" },
                { "an", "8348b12599c45e28d43cbc5b499cc608c6e5df1c01e9f79dbb4ac48293458b1816d696585f0204f02af2d09b7ef3362abde09b118e78ca3c46f65b84c8effedc" },
                { "ar", "25a9e034ac5916105b20de1b222ec549f4e0cd1d72ca4030eaab94e5d6403b80e74a56648f0a86270ffaae159590c612b87aa7f726e48966790aa6f1d60ed1db" },
                { "ast", "98bde8652fbf99201567a54322e5b5a9b32de2f68358cd000e4d9791f69e7be02cef7bfbceeb41738bcee71be462eb907cb03d7facf93b1a4a793fbb53420238" },
                { "az", "da3f42ac78c5c0f1d865beda05061d1d97875f8c35ce0a01d7a6286bda55065a32a8970bbfbae2c1069424b0ba379545ceff21672449d195208335c962c7239b" },
                { "be", "5701eb188c4df2abfb3bb9a9719216ee3c860861142a8006de948b19b6e698ea543acdb3cfc83cb4f3286808bb076c016e23daac551bfcbafa783f442ce0bbf6" },
                { "bg", "43740438906eba8e356f234a8ef92d3148a595440e65a3fa05c622db179490fea57f045a917a1d2df6ee9a77eed133ddb66a6083500848fef3492bb6afbd9819" },
                { "bn", "84deab374d68c9d74a0d0b1b16d18c64c442194de0c791da598c71229c4fd73f612936c6b078d8027ec5240435eaa3ed8dcc61c19b2c23bd73f75bc1b2bc166b" },
                { "br", "33862b46320277c6dc2e7d458e129ff1f0d847b8433b1c9b8febb582a95f45104425882336d73dd016924455dbf7e020b510a268374ef53bf1bdf09422eab587" },
                { "bs", "7db77e62dd14ea50a5e85aed75dc64dada3e143782459d09a0bd08c1593631dd6548850687432c15c6de1c658f39a4632ef323342017a9adcfb48e283c7b99bc" },
                { "ca", "ffda81081cef0389855a062a7c2d257649a593818f05805fa8b221985b733256784ecf1d0e13b0f88fcfeab8e7ea69e1e33539bfa83352aa1ef6f06675a4efc3" },
                { "cak", "c95059f2a778840377f06cc8f24a076b3392d310593ab9ed3dbc3974b69ceb7fa27688c3fba49c06b939564d0a490dded0f5f7d6feabb9a7e1de87c094a05370" },
                { "cs", "3ff6d2b3d90d35771cf76274df602a78eed3396cf8b44400c3edb2c0182e1554e80f68b0c09f16541f140e922abf6cf24f9c9d853dd3b446e1d6491e0b3bb4b9" },
                { "cy", "ceb7d591769f45283cff217e3e7f38baf4321af9e4e1adb025f99095555d2011c3c8eab3c544c3001200b3c631bbb1c58c835e955b52461c39124623fe55206a" },
                { "da", "e41361a29b479017bed6a568837330db9593c673da04b647fb8b8f016059f797efcc54cf5102dc1e34b9c66da7e3f943c04dab1a402be0859714a2abf1720fbc" },
                { "de", "ba2bf97709cb460419735289b65fda9999cf6d593b1d23b12411f2dcfe44fb771316a472146133e106ae7d52ffd9e6001d80e4b43ad09d870de85a3c6bf456cd" },
                { "dsb", "9aab507dbcabd89811d7afd0cf473d70fd0c1b145da302b271c0aa20dc1adc46fcac09a8a90c0206696b5697537289c5c08aa4607f65adc29196b6ffc372f9e8" },
                { "el", "2aa71d7bc0d65641cd2fed846f8591996cd61b9f2c6cdb41174aaec1255532cfc957b1c76cc8f4a0952252c6b2e190f0d3710ffb1d2e2016662dbcb8e8b215e7" },
                { "en-CA", "ae914197ca5b05e10e59bb1222330982aaebb18deb82f04478fdbc5e62814cdf9443e442cab20bf43cc0385dbd41a03126269d501a8e0d2036e0013d97c0d158" },
                { "en-GB", "1591da1396d9a1bf0868a919f40e08087d629f438c4d038a77390df760c74eca2108e77b5147909775c56211a344dadf6798cbfc578a206b32e02c2ad4b91068" },
                { "en-US", "25fb4e43591a9bc0fc62d0d1e55f32cdb29d6d21fbe6a6d903795afb3d1766de7db2a26ba0f8d4b4609b046810566092d5b8301974a8daf23e756111599c03d7" },
                { "eo", "47629581a55ed6ebf25954b6a1825ec2d7fbb7c2d863262327b388e7e7ca617a327d5f4fdb9d587796c2db34f98b276c9f298c52c5a5a4ad63337763dfd60cf1" },
                { "es-AR", "69a9edd469ba5bae25659d1191d99e9779b3039cddf7daef31a92167cde6a5e9d7327450e0120a761385395589615f46eb0929a8c3c9118bd5c0a6db739d0302" },
                { "es-CL", "9ea80b1ba5e4c5b6d1b0eadb549ce50363f18f76f206de34792aeb58f437fc1c6554f7463a687631166e6bbe14b9bfd6ba384eb1a269471c22305e16c30de6d8" },
                { "es-ES", "5a5ae4d8daa99df1694b5e99ae8f83f4f887c886dc205fd94ebc6a81db14679687be42561b382a92f25f4807d2bab0d8c725359eeffe1b6162064a77b4c0747b" },
                { "es-MX", "508529b83c1438eb5bb6280fd409926d0cbf8325678921561ec15c52956dbdb03678ea3459084f8f4adcc96d0496c5ab00ae59587a6a343791f8f55aac75c083" },
                { "et", "0ac62df52553be2bac329e9a6ca7852c8ec0e3d487584e85b401b28dd74a030bdf15f10655c30812ddc7a81366812640b156c213f696be6b059e5fd440ce97b8" },
                { "eu", "55d253e1449cff5d8cfce49e8c593d7d96ee40707f44d6df0dfc220b2abad7430d7f0a2a9d5cb216e6ed6fa5ed6da36f17556b540d14241eb9ae7bee9ab7542a" },
                { "fa", "9991247b50e8ab1b8e688f695ee9616adf15a83a383c343ff292e414965b3da2c3a85ff0f8be35678eb86988a76410ddf70f5968d4a1b1af17a988a92b53aa46" },
                { "ff", "3897a08683854853f6b0c4e09df0194ac05130b49c0bb733036eb00c8515b1c2c20f2a80c063a85bd1d7da6705690d993a65023c6b3b18dffbd920e50fc0a6f7" },
                { "fi", "22ae0d42a834de370a28d6ca0c24965b7a49091572d858b3446e1dc005e039f2af762a39967b13881ce2cce58ef859d045b2f6cfa2684cc4729df6f9f5b14196" },
                { "fr", "c3bcd45e2e534d6e0193f01b1af3d1489eebd77c1df21edfdd1f24d1fedfc52552755220420e4fb149cc1d1c863bdb9bfa48c4306e7c863e305bffbc4ec6c360" },
                { "fur", "d86e881f8ff6a68a5382b97b629a3e3dfe5cfcdd7e2bae6acfdf0edea17af63c44b325b52343170ad313f4e5e53b1bcb34c8c16f2b383a1a2d2a8ca4ce802e7a" },
                { "fy-NL", "29b29fdf12f5a05cefefd103193b5a88821566925d07de148003c75f96ca5003cd98682dd882abb1271fd5d569cea2b38dc8cd4b20bbad1528a1e7ee2ba6c13f" },
                { "ga-IE", "edc22846e8e612c22948b804e04a0705d3a429059e4e937d500e5dd13186881a5a113cb3aa66c4f50ef99ad1b2ffce30d876a0693c3920267de433d81d15e6c6" },
                { "gd", "a3b7df3d07cc41695bb88d88529962a90321806de0670c30c1ec3a5fd660cc82cd560d940a772891f8430e74bf1d32540c3cc8b9e5f5e9e1115eaed74a3bbc92" },
                { "gl", "d553e7cec96ae510ccddc928210e265848e55a27be72ac7d74b5736af0791647f342b38c98a534bbc6cef519fd7ff7f7cd9339f879fd8c8250928ecdca543d54" },
                { "gn", "72656e01ab5028437da47bba5c6cd183592369a277783e7dd89c7f9bb4cca3e02143d51ba1903fe9a39652daaf2109929e31933c8db3032b3eeb51b267ce23b9" },
                { "gu-IN", "47f61dd4e410bb0e9a9e53409d2de8672a1638afc6fb65c512751d15a5aaabd63f8694e78a5c731a2e77ae4629bc4ef23f4367677dcb97f7e413dc141742ec52" },
                { "he", "819eca46884b88c29e8e0e65928fe0b5c9c1028ace541280cde3a10100e742d479dbbf41787332c4123797847dbc5c36e426bf8f2a932750da5a3be0c7023c2b" },
                { "hi-IN", "d3a1c61f49ffdd12d49466516d06a4f3319625ff96729f8a695f7c222fb7a1aeae00a179729565c4f08767d88cbfeb9fd47f8cc17cce3bcb852097e6bfcc61f6" },
                { "hr", "dd4ccaf8a45d89dba5ef8adf5b6201f346b7451737b0258578fb54fa3ee520795c02c8863d48ef2bd4c7a4f5b6ccd69777d79af7a1539ecff2130057eae6aac6" },
                { "hsb", "aff1980ecea80b87c05ce820b6ccdc9cda23accf7c0c34be72d253ea761eca3029b4d23730a838737f19158644fb9ebf2955442cd7615ba8cf1620b056ca0e24" },
                { "hu", "07d3896ae591cce437186374d1043716edb4a297beda09abf81b4b7016a0c78d5967aad0e592be099b093fab636dcbc8fe8dae1a7312a0769a1edb1c46b924f0" },
                { "hy-AM", "ad861c8b59a5029789ea59030a32be2274479c9b49a04be7aa65c04b219a13d2c464dbc7ac2d838c826837f912cb3f53b0e454ff0be5240a1348b2566aaf2b09" },
                { "ia", "27d1817f2c07b5d1b75b10de568490eef0562687e6a64076c9dd563a0ed028546acf5f402d7beb3a76f2fffd84f484279f92cf1a78a845c42386551d697e577d" },
                { "id", "c2f793d4144e0894d62334cbc21a3543218fff0469e8efc054dfd94ca2a9bf8deb036ec06b4147dc80d1164b9422285606f43342e543568cc861df9b5c04d889" },
                { "is", "552a71f9d293bbc233110d1badd08095cb711d80d1f8e60539dac54f1ea5ad1435c86a8de5be0ca95bf3b3e4367f710016af6d6dbb0c48273b880cc2fb1cb1ae" },
                { "it", "f184d58d09b3d67b6adea53887b410f56cb8764332f3a858735e7ba66d58f1e548c4c80c056512f27303ec4d980c9260b8dce7efe5c4c35ee6705b3f51d1fe1a" },
                { "ja", "e07abae7cb29a248cf8acea8cc0ff53b2a62db38681d5704c5066d9da6bb418d56803864a40bf0751c7a06c4aff7f8601edee06276182633f6b648e214ae42e8" },
                { "ka", "98476ee52245b1b0c5267f510502c2bb362af2ad2c820210a483fd56845fd8a8ec42e49a17c9237cefa39867326d5d0ea45f9cf11146c043e535c1e22cbe062c" },
                { "kab", "5e9d01c5a4b6138d68763871d88fff5c637e90115234c6790cc2aa179aab52464b189a99a0d36421c59dc0e2af8aeb75974e3b06f09dc066f6a1b0ddfe799598" },
                { "kk", "445533ea30e7aa20fd49d4fab6b21d2c5c77453a0aea25d31532dbfaaa7bf2317cd1985cfc0ee169c3cbd44ea1b9b4f45bdc5815f7c7e0d4f8f234a8b58bc564" },
                { "km", "492457d4c8f622e2773f537da75c4c4c0475c6a22258c8583cdfd4916d251cfb249d83c8243821c87b14dc90e5d8341e6b5cb4ba7016eb6929bb2fe7abab8dd5" },
                { "kn", "a53e7935b7fd32c4e49f7178f4413e05f4355af377b1488f9f75a698e034ef25855f773eb3f325373c2b4a087cf0400512052e83e95f1891bd64d6955c30a1ed" },
                { "ko", "720c2312da68fa07221d195cc76a061020581bcd4b1680fa2a77aa7d6a8f2ea7f9d3d73f6a36751a26083b4e482412de68bc048bd282f86a1ef08e98ecdd3c1c" },
                { "lij", "11ace04ab7c1f282e0b62ac9e6ab23ee8c797f0da2cd9ba6758ea62600f0ff72a907f81685bfa3479c384f2c1c111057493f900ef98f89847b81a3ed3e973609" },
                { "lt", "889738e8df38a8367da2544a645c880b25f642236704e6f845cfeb1194960ed21830995ccc67bdfadd80c9adfffa0b75cd0bfb78bd1e0ef984efd9dc0ab2453d" },
                { "lv", "eb4ac702f04b19178beff22e012b7c08457fa3369246bbaf1e03174fc150ba74f038b99176290f87262beaee2b5252f46290ac3c2dec39546d014c73a6bed14c" },
                { "mk", "262aed0e970cc22aa884cd1bfe392616d2b93435c6e01f0b274686ace1f079489b744fef42c612b065b5a575ff8d6805b1c24cbb140e91453911b1e98dd2d815" },
                { "mr", "d46e8e170234bb8a29ea1dd43f9a0a2515c252180a72cc4f0fed0a8668cef69844a9d677cd09005d1dda8608fdf7962965fc244894591c89288f9fc1d0788f84" },
                { "ms", "f8f24fddd96306da92a29e8d6e4ef37bf4d6c4186d322dc90656f6e7b799a415953368315ace7f3219b6486f3bbe7c4e605cd22cc81b0735b2112c550ec1c1f6" },
                { "my", "0399cca22cbef3b4d67b9c4b9d144b9b794b98ff39f173bf0a3032dc83290770eb544b956ba3e8781718906ae863ad4ebcc607aee46d39a43eec137602ad8956" },
                { "nb-NO", "e25b98b6c8561ff6d29c3ed61e1d62615673ea41a6868cc5311fc8a1aaf342e51c0c280de43f490f20c5b8f1ddb0b9b6018342b844e176ca03f6c9536b0f81c1" },
                { "ne-NP", "55dbf337226a76a05a2ebb31cdbf0ac5bc8b310fc7d7f4f1e5fc2c2814986f511fa8bcd2ebb594208e69b7622384509b0dff142c39fdaaeb0ef56012c1890c66" },
                { "nl", "19cdc5d4073b987f8bf3c198536edaf206af1ce75cea9b45347e3c6d82639c8e03d85fee3aa41928d5123289e1498c4faf123c173290001223a113ca16e759f9" },
                { "nn-NO", "a4cd42f0f90942b984a2ce390cf748b5319256dbe30d9166a08e71937c1f9b87f33613a2f83757f19ca285cb9ef54b0ae1759afa433f94ab1e2b37e16d75bdb2" },
                { "oc", "8a83b369ff437913bb83f0999125c1080ca6f0912519250a094a885abe6720e798f037ddcfcb75412078607efc97e102353667a0980c3ef867084111ad554eb9" },
                { "pa-IN", "1b0303c6a70dd475b69c959c7630ec6dad353dd708f53b45aef9bd674c3aea209dbca34a2d6957de81e6f333e14dfc5e004b2136797e964fff9d5e23db769e07" },
                { "pl", "b3c4052027b03a16e632cc7d9c00caddb9108c666350c4276e0d24ce1c9aaac7e48086661abbc9032907792c27d8854d1fd20ae6564a36adfd93c25fb4e9a75b" },
                { "pt-BR", "54dd902633245bc2406d696c40dc37b2156113f9e521e47573e9e5771d85558193a92bb4984f8a4dc34d53fc672f775affa0988f02185d7de6b092c0e1bc1e42" },
                { "pt-PT", "d21ba5176ac4bfdcc1c233a32622a2ca3a4aff838978d67a107af1a0fcda3d9f91a714c0d3f3694528f712f83ff30f0aa0513fba8263a3570df3cfb999c7a74b" },
                { "rm", "d1060e978dd236f2997c55765665ca7a951522b40adc79b7813d7d52a56293fd27d3effe7367e1c552ad05df0a38ffe710109badf0215342ad747e65739bea1a" },
                { "ro", "bfc526631508111238978c3427c2d6898a4f55e29573d2d03726c1de2373c9aa7d65c3d655b89ec542caf45e90c3b45fffca52f00ae29be508d4d9cab768a379" },
                { "ru", "ba2aea212ea2c07b63aad88e7ea21b3bef5acbaaf5ca458cdbafe8905d1830b2bf1baee8c481f80b3f76884c80c2da18fc2f9f6a320069e452071a6c0ac4cbe5" },
                { "sat", "696d11279f918fb5fb20088871879f59fb968a526af53d5c3e3477aa712e4874cb11211d679b02dc743315210d09deda78d4b86f7aecf9234f0b13a4a64f9238" },
                { "sc", "0c8fa47bfba13498fdaea150f7cd674587596935d3a365093053280f1eaa1fd4c4f1ac428c1dbda656116e343e0e47592cbd6d03b5b6ad532a6f4d53bb4633e0" },
                { "sco", "fd2384db209d760d3d0fbd97d52515f7d78e9c14b384d5b9d2969db929ef5f8c08ddb2f8258cc46d9950717c83ba448e260c3960b1253866c23f325357f94d6a" },
                { "si", "ca697ce27a3d36da2269b4fa266b24a9edf3e729240d1185732ee9885af3e73f2caaeaae227c4e66336e9078c6a8641cb2b36fb1ee2d23554381780c4d3986a5" },
                { "sk", "0cb34a5ef852734926e05c2adf52a760f3b8732c499c5315bf435d9513b270011742e749729c81d4f565689ce90b01de98114725694cd18e9818ab4c77f7ad89" },
                { "skr", "d83d62d8d50423ff33529b1f92f6421e237a1a88efdd3332eea985d485fdd20b45db7f952e6d05da7e40e68bd43f28715d35f7358d123ec3191d5e4c04a06781" },
                { "sl", "f5d0cf1d6bcc39a7a3d42da8c3c0ed3c229e95c29d7c12e368acaed53d92b5a23df9c1cae0a22d2367241c28434f7ac65b8a6e8598b32da45d67f277910aec90" },
                { "son", "4b2fc7bf1c7ac0b6b98ee1cff25664c3b149667d79b34232b30c58ced38f76c9b6061e63f7671f0bdde85bcd13e6bd74ad6f7935a560fb5d04b9fabf73992b3c" },
                { "sq", "901ef94657bbe5ef6a146e3184a5ba92f0f030a4779242c1c858c1810192709b1700862010f52458fe552eefeaa3519c4750cd55a313e1f27e769b2c198342b8" },
                { "sr", "792be35b12f48e21f9f361c800b3f80e649e1db948fd103c286bf351b1cb3d6ed986ae5ec2256eade83d89a0f60b1e9a55be4529157e013b59fcc144b5bf0ff8" },
                { "sv-SE", "b6cda6aec7757c4397336e633bc3c0b317c113c5af7cbcb17a47edcff9e99d14ce2193fee6bf8745c1d206988e73a0774b08452f7d90d901f60a8e223bac6fda" },
                { "szl", "cfd40a679406d9c3d0d6a035ffcab3dc05b15b8f6c4ae8aa1961d700528ce03f9301ff1b0b4641fbf0bc025cc7c134ff269dc27a381abdfe77c5e79523b4f0c2" },
                { "ta", "2a0b29ddc342458f5a02aca1a2378122b24e31bbdbd7f91d45c20903b68259f09ee5babed8c4a9659ec45681445084f81a0b7729dfda0c4742fcd52f17c97fcd" },
                { "te", "7ee4c39804a71331e514b586a03c7ae3298c1fe70a21dac5419748047594183fe928d8fbf3d01a1661c6f7af6721c3bfaee4538debe7eae46e5e605eccae98d3" },
                { "tg", "88ad7c985004691f8906473628ee256aa9a5931de6b4b4155e084de0732ebe3de02a3a86587e0884702a3146573928cc9d22162bac561c6e5d75db27460189dc" },
                { "th", "8673965650d5769a9a73f95c36445d31d5eb8203aab201dd749c4bd06b88417de682af940cd2e28a841e614938c6aec286c53a3567e2e2f32aeb87c71f34832a" },
                { "tl", "18f6bb16f38b543a192040d3166433665852774f26e27cf2470afc6acca6c82f0e236c2c1981bcafbcd64aa8fb658a4580c276f973c9e5e080dd476034808fac" },
                { "tr", "0516631603876cf1ac26415598afa7c356712a5cb0fa09d0d4093cc59785a90dcd9f9bafd192cab3845766496aa8702a3f51acd174813671851387869a46f71d" },
                { "trs", "d5c9e2327c010d62ba03967345596221f7d4273ba87f8a89cc95603c8637739253f257987223f70c54e02c20e717312ba36fdaa7bdb06fd66dfdec93be8fcf22" },
                { "uk", "535092543eb980075a5bd9c4ade2d3db4bad6a5d2278a04097092f03643ce4b3b20b2e9c78ac4e5cbcc3f19f0daa707b25c92693d30f02e8021d03141c7b555f" },
                { "ur", "5df91f55917f7532d4a7acd0a4abba7914def1b517408b28c8bab3c76c600348f47940d7d32d7321fb197867e071ac1a4b0873e6f9b09d9430440bc1c0b580b2" },
                { "uz", "6182c472cf51bc8221031aa139676ce9955098514ebfd1eda66ca9065d1e30b2d70d31febb44523ef74920402ab4bcab3445dd256b30f4ff7f859a3c2365ff25" },
                { "vi", "f4960f9e66e82d46407fcb4d59c811659bc1ee3fc049e368f8f4aa8ba3153e0c7b5a2dc68fbb23cfbfdcbd84470b46fb3bf5d7c2327d88abfc386a7e1636bb7e" },
                { "xh", "2141d43cbcd8d66e059e5b58128cbf5615bb10497ec9bbed85461b64669d3e5385b6d0a48e33c24494101dd148081c75c2f3ef157131bb449183b6e2e1b1df15" },
                { "zh-CN", "131ee64626450f86eed32588c4302364310ee20427b7a7e7b8fb97cd12a6acb67063a95c10345dcdd9397f390365bf67c3c75ec42e367ef3ce7c2c2e26a3444f" },
                { "zh-TW", "27404c0ebf17b9c46966b41102bd3d5a72e1ad0d1fed14c4f9280517ecbe9c8309812315fedc642dcbd2547f22e2250997dadb6a478de95ff0aa7b69e4f8a830" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "230df7b9ca7031fad0770b15a31efb854d431266c686d2fd255bcb0a7d02f40cf90d08f85ed101fc765be511b21de0c709af5ad5041cdd339cf7d9d206ba17b8" },
                { "af", "1b38239257b0b16bffe93b837309f2fb0cb5aea24fef8eb04ef64bde8e0bd4372ac1417b4f879937303044390a2ba23b6637288a41203ec15e045dea52d098ff" },
                { "an", "c0f6382d42d644d7372b7f001f5e78319cf73be32e170a8605631dc3eff222c632cbeb54916ea07c54e04f486feb820c50f5fcb283a17173eb4293bc6baf8425" },
                { "ar", "f4d6f5af8f49af5eb055273dbe4e99962736df4209dc8a37afc5c4f07ee3b086ecd6655f4cf316973cb2adbb21428dfa4bd09b3aaffecd8546a58662e30603dc" },
                { "ast", "9f0ea98086762a27c33abc86b79f79841b6096540959bb110071f4d39bcfbcde54b0516369b0ccfae5601130770c9503cd24d9251cd3831451ee08dee231bb25" },
                { "az", "35561b01c8aed4b3cb577ae090e2727058933967dff62d0f295e90e790754e9a70371b7eb7b8c01b9a21e1395b78d71f1112e8f85ef63bb701147c40d6a2f850" },
                { "be", "46dbfab0d437f3648f496c4246fa58340d4bd442066fbfd0a80d1493c79ef55cf7dfb89e86e3b9dbcb7de4996fe8a6b029c0b2499c9042f057daa57fed68ea4a" },
                { "bg", "6c535d9fea6f5afbd262332333b4710edf9d72879772fe3b5ca543b8727892d1bdde69d4549c4076eae061aaba2a2fecffe901a098907d340c7fffe654f86d7d" },
                { "bn", "0bc645a9772413ccec9e36373fbce36635c8c571c0623a3b8b12b182fc830560860df54a7b3934e41295938df8eb159317bf338a0aba45b1f0ef8a391a8c6e72" },
                { "br", "4b1aeb085b400d268717a3ed9210dd7fb340df7c4cab58cd4eba5b185658a4d4a1c49bae28d0092bb79ad792dfd4789e9b8155b5fcc9c52a789d88058dbd738e" },
                { "bs", "e98795a5fdaff16133d25b6880ae8892be44f4748b17ae37ae48deec38123f282a801667861415332279a55e37522b4656eeea9445dfce8c23b52819558e0bd0" },
                { "ca", "474847e04f52cdf3233cb92de2c8242be4f7db8174652754e89b19e6bb0153a64b6ee0f25dda8931087e9b474d442ae686a6f706f1a700aae9ec6e56917696c2" },
                { "cak", "c66d2c73a145ccae4fd00fc604cd70649bd4662ff213d7342963f00e6637379ba7b5f691dfacc299cd6a9a58b6eac325d760147fc1c4600400581079ccb6f89e" },
                { "cs", "8f73eae4283bb7c678dd92f1b96e4bd088590d0fec7b0ae80cf0189ad564c27fac7ec77a6c429782df0cc5c215f3d179eeacd8ec668d131d83600a7a36bc9bc4" },
                { "cy", "ddde3237a22bb3d9afdf3424b9f2d04da6bb626e0d4c51e22dd45e258cd3eff0b4e909bc1e3bf14515bc71c58e775a74b82ca58ff14be4b761ce211a93fc3871" },
                { "da", "4090737d4dc048f3e4ecc97a954b2fb5d07a3cd8b31906c6f077fd21143f80abbffb5940074c69de6514dab68482e7367df6c5f491fdf51073e00c8f5d0a77c7" },
                { "de", "b6b9ebd27182e893fa3f88bd04718fd6060182c8f5a7a0d78b0db9ab3dc8c8edec1fcca632f97547afdd76f90625e5d1e491ba5786c3e1e201aed4849a70c90d" },
                { "dsb", "8a4ab1a938697245433b91e3b0acb5e5ad3ca85e8d0f0374e917ac99b694b6deaffc322195f87d946aab0d5def64faf61562e0c1a749e918e11dd547682bc6ad" },
                { "el", "f786c9787eeafb16618e10c3abcddee5f359210ba54bb4bf880d810bb754a9bda714123b593ddd66c5d2d50d236b95278b98cb2697ac4df02f24c476dcab2144" },
                { "en-CA", "293e6891099e634addcc66583273931928c1cccd3f126a694779b85c16962b21ac7801088ae72648270e96b2237a9c814cd29a9bb0547d4556810805b1847ea0" },
                { "en-GB", "09c19923e04431478adf1a4a3ac84327d839a9eb719cb3eaa16f38ac9639cfd98fcbc83bfc81d547705113a87c5b55104098e3664cdab5fa880ceba7ede81dd4" },
                { "en-US", "ba9f30e439fc997bd073f77ad2fa3984d6b0bc79e2a20f08ce4a6ba3f65eac82678b2d597dd42d567980908142abf8c60b11da5346793ff8675c34817c38b737" },
                { "eo", "e2e884579b3c3fff4b3e1f08971a2b63520bf95b0461fe16b9cecb37ec63dc05cf494e5243eb85e8f92bb8a74460eb8760c190824944e217c18f41c1e205a383" },
                { "es-AR", "90d76fa9f679ef454f0ff70dcc009d4f142b1b81fe4def45e3e4d85b39b60f0f999aea843d879ec173ad0df88642f1f840e29ee9c713f5a7036ceefc2dc1b9e1" },
                { "es-CL", "cac94e738e3c228be47bfcc59e4825abfff18a6e2fff3b5292bddfa5e266f89a3e58a93c29fb067f5c8bd90e8cc2fb7b18d7e383b33367a0b8e1d2fe2309cc1a" },
                { "es-ES", "863cb16b133de22661dec8688809b28e68b4f3d6e8d3f3d61e75c129752b9feceed7b77eb41a7fec76f378a567a3137726f324a73b26fe33ef89d32123854e69" },
                { "es-MX", "e0033bffd55f82fd3df07f95750b7ef644caf1f8bd8c4664e015b9498188104f28277903c1612f72197f6b02321820784c75001ec242317fcbe86ce7344408b0" },
                { "et", "62c7895faf59dbdca9af33cf43429a690ff72d7dcb60f2c5dc0d3e2fa192d57fa071a284a00ce33265ef686eaff62bb8df2db27171ddf040ad5314f54c212bc2" },
                { "eu", "3e09f892ed9bcbe90aea0772a1a034f862399a1a34eaddb3ae22d75ca05efedebd5f5e76dcdf4dce4b075ea15dadec2f6d9da73fe0383254d5a92ee9f5a73582" },
                { "fa", "93c8d9a7407d0e54c6d5c2f1d4f87d57416ec99cd948d5ee02b786d50e85dc23806f40bd47a98ebf44d9e4dc6214d24595937feac50b67c6dc268418904df03d" },
                { "ff", "9691d58db56da8bf1be2738627cca10802eeda5524729297b43f8125c1b5681e96e581a1d3d9eebbf1b288a224195aaf0fb2414d75d335fd1ed6cc21c1cbd62d" },
                { "fi", "0fdfed61dd1a3fb51695c92f1229efc807206d0ab3ab4b77722e4d1deb0faf574fa5cc8a748711c2ee10e34be02b8470892e3a035383578f31980cd1f739a043" },
                { "fr", "ad8d2896afdb2db2db4785553b8956f7f211ef2d9fe82e6d2e984dcad8345907dce1c9f8cf7f3d9d6cdad01097151ee5dd22e7b179b6c0758857968318c9d53d" },
                { "fur", "fa9c78c6a73d7814192aa93a8dc3c30999e674c9bbec690ea8ae0a64ea727af397ec4761762ba887b259db73e8310ca4e99d858b92b1989fe16c34ac7f91efdb" },
                { "fy-NL", "6054dc096c1626d3cddfc76ad2cfc7b1b5953a92716fa5f1d031d561b5c9635a78883e784e710dd1c81aee16d0df4dd48c7b44cf65c67aa528615d33f7b4140f" },
                { "ga-IE", "c51851ab7ac69406975e1b842d3119a2ea37e82db2b76a9bf5c0665b3256ebb27f0c8a8e1f3c1ac84f1820b1f9c56254eb4717217f13aa8253ffadfec3307570" },
                { "gd", "803b47e73cdbfd96ae1db4ca10220225a1aad1a1d88a6202a29d761e3ae951165565c7aaf4f88ea3b4df7d21f401f5874508890d2a066c334eed43a93386b77c" },
                { "gl", "fd24b7eff29e588a993e0e9f97cdb9d0076688480fe98668d7c4f818905a3ce99317673a6030b95fd4dd34d9cf045f6b4ed56be79c9eab7dbab140a17c1da175" },
                { "gn", "5a674a440be7730623a932b73af104705812fd5e2eda6657110c92e731fefd7ac6e0d117770dca2577145b97990f236f14ba69d6bfd71eae3bbdad7d6d9f02e1" },
                { "gu-IN", "72410d654383ef28a21657d3d74f69fbbc37b6712d8c9119422f84d6dd1d66632e035d22abb74bbba3fb190bb26017cb92b5f70b96e75c16a39730f6340a7b41" },
                { "he", "66aa320a67d2481f498c08a7c8e503cec82de54b48d01d5936da5f4bd3e9a479d4883b529afe1bf5513fca10521e8a585fb7002ca42f992c74aa8e212fc23194" },
                { "hi-IN", "67705cb09d6dcbe024bf1a737c44639e472680f626a12654b40b3a3e42238b9176052caa97793e51a454cb60a99b5dc8ff40f67c8f43e9f721fc815ac37b462d" },
                { "hr", "630986d3185f86175c38b7c4331e1647f5f6e5b1fed37f663a96a38965f509a43cc0f6e7c553903ac2a1d1b3b448a85fa0fc59bc497d23b167adf1a9decaaca3" },
                { "hsb", "186b2a7b21d9f7f0a192537555ea12b95fba7e5954df57d079442d3b69810e0fbd7a2b8b16e5f833b1c45fe858c4d109701d270d8cb7dd2eecb4fe98ec8fcc1d" },
                { "hu", "c0e3f19d32565d22597273aec64092acbed7fb715946d13c40d921cf1673bc1469b7262a0c3484adfa62c8131862a2d12a8c5d8006622da5df46ce38a9cd7607" },
                { "hy-AM", "f7fc8f379c4f15be4d4225be23efd8d530457f89acbbfbc6b6dd38acce46e61c20433e3f5fcd86ac159748c2d00352538a79811892eff7f557db95430ad7c148" },
                { "ia", "d338fcaef9e089a25c3225c75a6b3d29b93170dbd19d5f160283aee5a79106696e1bf98769bb25e92f702d9144bbd158669ed0c0eafcbf6d2540a769d7ac6ac0" },
                { "id", "68708334f378b799bd6aad3c66ae91d4a285ea535634e7729d52331c639fef8fdbf7d93b13324956f7291257ea3bfa850b822229057a5637a1136b6608a6326f" },
                { "is", "6f23b612088e752d53bdfacf60636bd9b3576c50bcbe1238bbb392412687e06a3eafcaa099f19999bfe3d9939b0ba95e60c55d2e7644a9396055196d992d31f9" },
                { "it", "8df76d7f13a41f9fa5a21a1ad60cebe6fca3b2ca0bfb83e11a384d160ab17bee07ff8ac0fd91bc1b95c24f6fb3d4f33238b32c6dc3f3b8b7dffc064b43a60188" },
                { "ja", "3dd741c4cc0f1a99324418bf0723bc76baa1c358fb2e10f972c67951c86706f6690b1d67c8d2e8bf4219d062cdce82ed0912c2dc300f69ba632d925801d32c80" },
                { "ka", "4dacd0d87a88a60e2268c5a565fadc9901c9642bb553999cba424abe7ddcb8386b9a48408518f6c39f04a7215b6912c0a19ad6ebc5f562e55e6f8ec23ce158f2" },
                { "kab", "10efaf13fdbf02af569b14ae45f8f60d7636af7f63634a58e3997dc16cbeb968fabe8ec095557156af3610856b8c94b0ece1eba48f1ecc790389d2c5a95d3d21" },
                { "kk", "c637be0a16c4713ca7d44a7b71fd956dd5cffc24343e5ba071f85a353f2491b3be99ea0948afa210089a2d537fd0a279272a0bb37fb13561f243f08ae5840c91" },
                { "km", "584deb6fd184f76cc93070638f250d0f2b14833e6ac6bf7d1f51508c9c213321e5de6ae36781e2aca459f4a7436483dddaf0dff8c3689d9f14224e802b6030db" },
                { "kn", "bae32c565bf4e2d104ddd4989ac49bdcaa5792e03b490ac6d8ad76cd3e4dba5297d79331ea056bf70fe418b48ff722813fad97f2e9e4653d6c31dc1af899541b" },
                { "ko", "4cf4e5857c05a59f14478c8d6819928c686de737097209eba21fe99cbeca9b17ebe7d5702f0d8032a43aef28b46d4931ef89798d516f7313eda86166e401a61c" },
                { "lij", "5b6707773a04d416ce5a09a6fe4053814ece1dc425a0020f821c3a12d025366919eec6d1bdf97d7c22449e8a0744dd347377690a7d8c44b9bda45fcad6836562" },
                { "lt", "679cf01fe2a51d9239ca26774cface8c9834fda1fc42bb5425c43132d9eb38af71217f866ec0584144a419b52231f0b0c815b78aafed344140c3dfd2b5914d7a" },
                { "lv", "d68d80f7a0d2d9fa251a9238e04c47c79cf221023114eb89555b0a10761afcef67088d8f146a225d0e6ebaf66f2473c6b1b04c300f590c3ce8238f33575ac4da" },
                { "mk", "556c521a74198e42df7116da75910ecc855aa696a0f32a0c95135bcbbb3e5bcf8d0e9e0b3ed7d4d12426a6b8b65a89c273909f23bf66813e55686e87a02618ae" },
                { "mr", "fab7fc2a8e4f898f42e1d94544ea197b911d231c6af2798e95919b1250f3912b157c2493a7515366de911682df93b1403c55234ea68e9d2cdd1a9beeb63e8a51" },
                { "ms", "4bdaece8aea964d535b81a8b85d1b423748d86fe7f7e7e455260a6bf10b446399af1d3338ffd7989e865ab7a84cf8608b5a8afcf7a9b88941ed2b79370640a9a" },
                { "my", "b09699f8d58c5ec69eb4619a302f6aa77aab895de51fecf5c7f4b783d658a6853f16fb779943bbe9f5b93a7efc5c32bf4f4ffae28e2bb050cbb962cf3fc5e586" },
                { "nb-NO", "227abd3c4c163cc7c40221a99ab8f17e762ede7fc350ede0dea8b57587ca60ba7b5f6c8add90ffd77e73850cc9d92cd5a1cb412cace3fbd8e2b959169026289b" },
                { "ne-NP", "9894736ee647d5bc3da9a1a0fe3ab873531f0a82172197f687621d9ba49544c9281e108dc40600fed1d25dabb4344fca59dd6f88203d48aa400d0541424f9a27" },
                { "nl", "6bed08100756a21c2c3591b04127fd1e4e67ca4de4debd17f3de243bee0e6d4b4eeb190dd6cad697ae24736a592b1e7ab795235a7176ec156c7e66e1b0d173b6" },
                { "nn-NO", "ad67f2998962250ab112231b3d488daaaf8377a2ca59dbae5145457dc6d981909cef0ca6b030cd1751f635169af32865bb865f646f2f37c2d7134b4829360d1f" },
                { "oc", "8b0f06a035cc06dedcd07f2481a8094bee57c46c2cac22f4476a284e65f056068aff207f169f92c305d1a2ebe6200d08b290c3583c51d405049cbf43be20e697" },
                { "pa-IN", "4e3aceb0669ab2873953d425268c1f5f73b2538e6931b418c450d0412af6d68080bc3c3e69d38aeb37583c983bcc0d22fb7a57a82ffdc08e05d01e00f42dd207" },
                { "pl", "3697b5f53826c04c5f0dd32329b1638e85ae8aeddb09650a18159421e15d8cef20e54d023438a41e3c7b3dfdf35673d17acd0b7c4c34fa8f1fe332337629408a" },
                { "pt-BR", "29a172694957a3a24aba2ed5a68e05be224f6c70e2d1d838ab1dfaa0387ae7ec0b59a3a1f2ba20014e338cc9bff53c93c14f21c4ae7b1b6f5dae62d2a076b9c7" },
                { "pt-PT", "da576761350462afe8975a6ea7b806581528cbb01c2c9ed2378b0d691b7d87a6e976187c0deec05373e39704c4559cf08bec6d6ade5fdcbc3c4d14627651ff2e" },
                { "rm", "fa38e0b25d02b5e1171d6fca43ca93cd8323a0e4bb85ec772927b7f8301e66b7ef2919c6fe9515770f214278c495a70c56e82f846453dc809d49dab1d1b86b7a" },
                { "ro", "85ee35f77e15a3fc7ac1893952b2fac5396f841610d943ac65d55c4a26cd8d742cae4ab3484c2f2bd41bf1c94307e18303801a8e9f143a831f1e74129d362054" },
                { "ru", "1dbc86db9ea113f2a321e392d0ed4e0f2ded831e5169de684ab43af886807a835c541bd7fe573f50e64f7e3280a25b93c48c4f2c543726dc569086d5af48a855" },
                { "sat", "3148006a9d31ac5f86b80ae727b44b8260023ee94f22f46bee41e6eeca66fa81d6ca44a171ca1b43c54460ff3318f45ee3c314b8fd6271533a0bbc02deef2227" },
                { "sc", "1e78088482f29ae9f7450d705e61b766970a2acb3e864c556bb382a8ee75fc9ee2feea19310960f1e746372e4bd32e5baf6c0cc183c4e8a228a66b57fc448731" },
                { "sco", "d54e90bd12bf2b513eafded91d57e2873cdb946cecaa14ce2dea2aaaf4ec691d024561783c8f1d5fdc8d0d54396e340bc67cb3731dc35bec6ffa3625a51da28f" },
                { "si", "542b673a0f0916170f1a7a9d8b21620f4acbfce4ebae2c5a038c8fffc8e4c9674be3c636356c3da967fb52e6869dfdf0036fc69a48a03add8bb1e30afcbd702b" },
                { "sk", "13ae1b432259e967c255e93efa3b84c086c9878b6952d19ccc238a1fdff734ad8b03049c304796e129bec393576f712f6d50ea2a6c098f6a13f6f0015eb3918d" },
                { "skr", "5bb1c318f69060c4a4e4235c7af2ee462e983a8d7855c9dacdd366ef358b59eff6a1f69f30b49cba4dc1b0abf51e9fb1430204c2fc84ef36b489b20f7725520e" },
                { "sl", "05ede2b4b27a4fdc0a3081c12f4628c4ab1aed9cd829dc6683ffd3810f4bcac689023d0f4366dd9e0c450972cd02919931b3131ef2dd7f4ba7c201196c021af0" },
                { "son", "d670abaac98fc03bed0f267c3a7916354182bc823bc1d6ac83816da57283916ed083e687ca5cde83c99236ee0f656a747d7b8abb5af566849a51f3e3afe2d596" },
                { "sq", "07723aed553dabbb9af6333afd77e9dba6ca5fbcab87dfbbe1e4833db3963245f77f23b6df5be8e377063268d1ff5ad746a38aa5e88af8897fb437f953b4ec4b" },
                { "sr", "0185f990418b1ca4cbe46d832a06b9b758f10b074aa6d5a2fc2d46cab401c5833c03cc05dcfad03e98707da889efdd2b07e5f2a1819225c758aefcbfc60cb483" },
                { "sv-SE", "af5c35b06943c390e5ecb355084d5155d9ae2cce309755f0ed87e3697b3d4e2f5f89f6a0e9385ea221075b7138486c522ca9cda5cba5fe270463fa30150dae50" },
                { "szl", "1079da5183a1ab5c2a5948c5371fc12dcf29ccb7252afa2454e6780f4caeca789fffff2263a682144042c07f5f40fb6aae70898361dcbf3a07ab35ef10eb3360" },
                { "ta", "c42c750562d47336ad0f6121dd1ebaa1efa68cdbddd5f91508eb06cebfd9cdf50be05191ff21fb70bcb04323741313671bc4d830be76d38923c96083814b717f" },
                { "te", "291004113dc7fe4b52bbfe3faeb250c1920aa4c57186cb021660507ab7c19f4b31b3c09ac7004409940c1790d84796fa6f3c5f2a22a91fa838cece62123d9ab6" },
                { "tg", "a2b37df594fa1028b2223a83551e7eb22dd3f748bc26c5cbf0bc21f4737bede788871b14aa1c43bc03d9ab638e8e3ce00de9f4b1700c97ff6fa234feee12a282" },
                { "th", "16e1845f78ae390adaaeaf699652a9f3c6372e3ed5d77ed00b1251abdbcf64e7d9b445ca56a5b8b08d9d655251299266461f0c0445e318d1e7a9de3f17a3a43f" },
                { "tl", "93de8992c27957f772a7b3df8656555e03361062b266c2a9f14e7ac1e5ea6f82dac3ee47c1cef33c5160dfd764c5d9eb825169d9f7309918496de86abad1c429" },
                { "tr", "13659f9718b79f80d13e55af22b3e40bf80d5f024762b5c707e96542035e3c02304fdae64782df78b77985e6fa99b7eacd47e01bce3becc1c3b30969632ba6f6" },
                { "trs", "150b1161bfef293c409d132fbbe83bc17e1c71e178e44965192b4da2d1b602bb2558a188914573580c39712f18b129bd0f7b0e613b67d4d816757ae56438fb83" },
                { "uk", "6e8837391bea7ed1b7c7ddf88d61e38d875bf915801c8dfc10fe48482197aae9d84199ad94d29fe0b069750098354793e03a6089aceb51b304b4d60b1a902bfd" },
                { "ur", "4e10f59de4140c7e241f915d0020a6f34f9a54038a42b82c1a0507ae146cf228c0c76cbfb4a2b429320756b153207ae221db3181d19b063dc8a7cdfe067f4c25" },
                { "uz", "c2c4c3fffc9b73002de32eb1773f17132576c87c7e26576cfbac01a1267bb889a82d57154a16c9ce927c7d548a32bc92454885520c5496bf66ef1e0ef43492b8" },
                { "vi", "705882d5de1151355cacf899b5ab1c7a2fdb275be9343072416e506bbe9be7c8543073b80f7890f790dc671a5aa087ca3b94560e7f09a06b27d9ab937bb8d152" },
                { "xh", "037588bfa3a977be3362c7b1518b261cb50646509e75d1942e6044b39f7e1640a995cb551df59a4c0a14aeed27b4ead2ad96581bfd7a8ba1fd175d8fc30c0f8e" },
                { "zh-CN", "88e688e857bbdb4eb304b420eb455363dc0811ac3522ae98d81c8970e5718871f4a16f7429a2f157eeede3cf400465f6ff8fae7817237ee37d99ad3947e1cb20" },
                { "zh-TW", "aa7ce30a88bb116f96c113b3cca3a583220e5ef4608dddd88cd9f787ea545fe8046e13d56d3446f51b8f558feb7e9866cdc99c1fe03373cc5b302b3cf6151655" }
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
