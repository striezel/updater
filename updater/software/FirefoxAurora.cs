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
        private const string currentVersion = "144.0b6";


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
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "955081911eba2bfa6bea32eca0a31272b2f7701757dfdf9b0e9e303c7a4d9ab477230700b4c488880381d573715eab8c2af86eb6ff7756956eb4ee6c61c9e949" },
                { "af", "f51394de09d7ec12e4fbc6614c151164ff76cc3d5f0175dd5ea9fe22cd040d80b75e4a6d9966abc5ffc424e2bb86d4b4d8b0f077b8e85a1a18764a4a065891d9" },
                { "an", "3ce1734c9c403b1422efb258259615cc365e26ca926a430c03daa024468d8422fbda4b737c225de12299d8568c6dd07ea80be3650332a41ee0c7433bd34284a5" },
                { "ar", "b1bea4c2a00089238222a15dc3bb78363b399850fafad0f3d8153602cf48d40b39a8e13ff8609fd887f15e372f008b011c0043bc9c52ab6be10c431da57cc5f5" },
                { "ast", "05301de59cc7c1b64c69f24a490752dad9d2b224ef0deb3a2fc6a9b28c79df430697415afe50ec6f802a6830e10825b64dce5b4dd1e6a0bde72b2e2c1ab9b716" },
                { "az", "56ac1c132d99b3b602ad537c96798265cb3ed3be7fabf48a56811b52c3ef3c8185601d512d08df369f8af055eb71a7341b6dbab0002b68dcd476bbd554d4a0ff" },
                { "be", "cf80a75d47899238a3060bb9f96951e1f2fe81a20e1a557b72dbd2e672982fc767fb5f44829415647239e28fe431fe9948077d3009d68f731a28e54c63596bb0" },
                { "bg", "45590ef8b45a1a50b9bdbef2d2d960c0d72a492cfcd9730f07a8c6508b87f68cf306722da6ec266fbd30398c9791644e6b74988de93104b5d61d1a0c6077bc3f" },
                { "bn", "c77d8c8f8c4d558baf8f59b471e850d8c5f4db30a42d9e371430f8e3b1ca1d877e5624f023e4117d2abf249a477f43111541b9f9b466d8967267161718a01db4" },
                { "br", "54423eb578cc5d5db34dc29dc36fdc2c8c29cc5609aa003c8e33988ba635c445159cd742d0633dbb9d0070285b148ad6943f2bb404887ed1e90f06ac4cf6a9ce" },
                { "bs", "d35f6c84c03cb688b35ea532f326a54aa15221fb3973d9c7de099501d36ea50dc81217317f088149972d71385ee93e041ca8efa5aba5d980df51b28f990df933" },
                { "ca", "288dc985e720b3232270a9bf3e4aad24239f19f8071ac4421c81964b22faa97bb66781d5c7182ff7ff77ed0c9de81c3a663e7a7e5688e13aeeb6a45697b293bb" },
                { "cak", "63160a1188a8ba785b4afeabe7eb3f9c4561106d8e519835e746b6a1dfc2df635272557da9b64d1aa66f35c106ad34a2e387f342200513bac67cd4991d270e71" },
                { "cs", "9ef1cf8ab5b14f60d8cab66ef912a1d8e8ebd15e326b10d92be8d6290073bd388b02d26323123824c07f3c8ce5e70d274d65564d38618de66b621e692ff5fc66" },
                { "cy", "1a88425550c9d13fe3ce595e47906c0e8ef79d4da80b13bcd0e0c60a819a3881d74418c4b643e2a075a6682a46ab4abf3ebad2c2467915000b66a501aa210267" },
                { "da", "cc55e22e3903444381d11b1e9b61f0ff473a01eb1afd7aceae7d87d502f1395dbb789384e9c530712b2f46daa03db365d8333657cb02b3ad266715f41c69bbcd" },
                { "de", "380435fe3d79814315f4b1c8c1a48ee1b440a1fb5d357a023b67b92c616303f616d3fe122f68ab683eed82e0e237fd2b82448a166079760570b4f026930fa7d5" },
                { "dsb", "653b12f38d77308f065a126ce2e77e12ea623de92c895e6aae48121238b1f6083455c8195268c92de7c4790c582c5426ad9749922a531f276bbc4704b13bae3b" },
                { "el", "f2b87c26cc24287be3dfef1f71ca0fbd8ae630f78566ee87b63fbd0afc05cf674f4c9bebf1376fcc3d42cee41a31f82b33bdcfb43f5040e9026c8dcaea5d1535" },
                { "en-CA", "09f22454a5c0fcec8b6d278274a855936f4a7027efcd495fb6b6a7806a7843ba92e94609f680dd3fd97710246e3dd817bff0f960c21f31d9cc59688b3d661120" },
                { "en-GB", "49645575b09038f701be59f657cb1fb11239d77bc53928f496528a77d92fb9cd965969236aa975cdcb1d2a4123ae37a83cefb255ccbaa48bf49d837aadb8bf8d" },
                { "en-US", "3529e58bae20905a76dd0421f87b1d1144ed378c29b5710e192c1567010537dde73951f5cc2b51364a29e231380610ec9f7a6f855bee48f61727c61bc9da5391" },
                { "eo", "60d07345c10c8b8c2f3eab00b23371f6a3b01e185e44fd54a54038c40644c19bcc8f302b8f3474a7e177e245f48114bb47fab40e91cb3db09ff62fa3364fde04" },
                { "es-AR", "3316ee2b95029759de2646ae5a1aa8e62e16e059f0d501d0b94a7e5c712304ecd4642bfb0f029acb814a358b9e1e45467860e443ba8575489af98eaabd9fccc6" },
                { "es-CL", "df3e3f5b32e36c21fac1b574c5cb3dcac7ebd028319bcbf46aaafe01a7fc7cbbdcf707f48d21dc4220d61119c701e4dd36706769d12234db1652f701840b9444" },
                { "es-ES", "af3c23797aa3f20d85a80483498f5ef19688ee62842e70d229d15614261e21cf56818b1f88d06adbaf6af055e5e119c1f625db8ad72bde3540306a4a84d6ebf0" },
                { "es-MX", "8b90049329081350e9b1ebbfae7e252d3735ec6c48a02681a2b2b5594e080da255c43bb9eb4988c5d7e28049c37d984f4ee1f35a01728ee1ba299bd166679284" },
                { "et", "222ee4172e0cf9eeba10d5538c5a3c08151c4a1bc4da18282f5f594cdb023918e383449e2b22f94f1513a9fc24abf29bedcc30c25f041795ddfed19101aa763a" },
                { "eu", "9a457eb13ffcb2b5706e08d2efe5b96f95873d2502d4bec7834c51241d6ac0f6fed80af91cf7aeb25c4e695e9ece71c6f7ef2a4ad0a9495ea2a31235d8b15be0" },
                { "fa", "8bd3d7f0b6ec8aecc3622e8334196fd2a57d26ff1fefd0bc1be764a1a9d569d5c7e42e09f064561a404c012ee2adedb0a2082253246202d1501b7fafa50deb9b" },
                { "ff", "8eaae2c2bc49d8b81083ee003d33a253a19c6358fe09798235065757d857c6b2c960785dd17bf3e3078baee974069b380de23072e4df946258558ed8a3056d2d" },
                { "fi", "ce3531205e0fb0dac7474438a316d3940470944c4ab446fd86e826ef7caeecdda527ec7f332ae99f8a6f0132334e83c8212066222508444685167c8423742e62" },
                { "fr", "25b244ba9401274bd2b1dc7251638fcccc1952d9d3d08d82f440d11af2ce6423f516c32b0849ff432e43189b42f6af4dc514cf90dc718c759cc678163ad019ff" },
                { "fur", "95ecfb2fefe26909b9775e1b17749001c08e9b8d14fae11e531d2a585ef88e0663176514161fbc4919c1e0b0947df14550e1e3962a1eade6db7ee4fc293443b6" },
                { "fy-NL", "36d59770f36b6f09624134a67ea7b3ae35dddfd8d4a3fcc18579854f14837f4ea1711a6b1f08cd414fd2453d50ee3ec23d90fb8b7371419e8618b35dfa15f51f" },
                { "ga-IE", "a0095471c713be9e628ccc4e08fc91a75c49eeae54e3f18d5799c3cc1e90fdef03d5a7e8d37a9f5089c9e198ca6e41dd393a4736f6085969207d7eac2f97334a" },
                { "gd", "b130a57fd154b0ae7300cc0a7218cc694fbd59918bbfe3185eb62977448b7ef74fc3ae83564d3e8087274f158889e071336f73f71e22c793324f7f637461c2e3" },
                { "gl", "8173c95ccc88fcd82bbb2225dfbab3ebe952c8d437fd31f56c1b2eb73514d47a4e79b1933a2e94a30a2c1c2507df0db89d292cdfd56b7a0b067e79960ed8729d" },
                { "gn", "1a87cc16b7e392d5d7c5db3f485941400b442b43cda9d4d4ee57bf7f33570040eeec7d3e66c2fefb2270a45104176c57bdab294e49a77d26c89e2752c55be6e3" },
                { "gu-IN", "3f308a46dabdc4f2bd74ac72240f50a484067686e0aac82670da7095fcd4db3b1bcb27c16b416e4cfdd39d0ca7237f1f53a187435ebdc79f0f60a1300f54f494" },
                { "he", "f54a57a59ce133e1089ae68c604458882500963d9d1b068d964c8f02603ccab6f034ab6ba33a374b7455712203be5293393950a5328251c2daed15001b84ea2b" },
                { "hi-IN", "6b52298ad3b9b5ca7219ac285de5e285e34ccd7132c26dec850aadca90aee044379937c491348d75f6816349b8ac95902bb699ff3691865f2a884a8baef8742e" },
                { "hr", "6cf5f1d9cdfa7753e25e6d4894d80ba910f33e41e5874059a0aa2b8fa83d3460df4f673f65ea49a3a6c09116f9139e56d3d2c0cb3db2af70c47f53aeb6e89a86" },
                { "hsb", "da100f48f009523c6b8625f387e513c808d7bba7f1ed45da8fe2bc150993b46b54889f92e2a5c004e36eeefb7ef029bd4b0e4c03e8e49d3fac927f34c0917f12" },
                { "hu", "fa60335f6ea6ab4aaf19ab79c1486d4edd4493a5e424343abd0a4501ac00ef1e6c198262476dd5a37c676bf43194b7ee512cdcd81115bfce9cfb682083b815b7" },
                { "hy-AM", "de1a9db7d54bb17669d827f3ae919cee4cdb300c06f44d221aa88b4fb446636945f220244d64c6f4d5ac34f3a8623aaa34a44c04da1e506a834d5152dd432cef" },
                { "ia", "3d278a79f1089d202f3be58d9049041dea7bb8e94569b4e599e4380c8b85f54cfa7e82e27fb5d981e48d779cf9e34362586d4f33227234ab1c522f2b4047aacf" },
                { "id", "0b05bc4c890c6f9fe33ecf8aa846d6a4ab43ad378ba30fba16c8bba0b83bda5ceb7a71726e205570a99cd8040c5f8cf4729d73791afe747194170e03c20e6f6b" },
                { "is", "798af21a164fdbc5ec8404650ae03bbff0a20ce63367bd3e8cdfc16ac95acc6a5054964aca989812d7d742cb0c8ccb534143e8957534380b833b94df88e7a418" },
                { "it", "1f333cfaa5d404746c3c181508016ade5e2ccd05b164842e8205e0da4c726e3974b843952665272c65a2c5a661545bc45f2ac05925e6a4e8e45f826d645ad237" },
                { "ja", "59eff4c356e81ac68b6054b19753707db2c49fed3047543ac413681c772dba19280515c97092ffc2a3730e2d38fdb4ed16519de9eb7eec44b5e954e1dc8eeb39" },
                { "ka", "30bfa7c3fbf876cd2fb3caca0b624c76c17e6cc1aeebf7d317d42823bd58511120e722c99cb3f45738c19a68c39401996e23b249c4d30262eca5c67f1f94bc04" },
                { "kab", "19dae2be058c12ccab1d046bf7b3460a9e9891623309397f330946510c4b11d70cad40fe742eb4b61d8a05f25e31373a8ffe5b0e8c7869ef9995e87ba39c4c17" },
                { "kk", "70bf4981572240b154c812cbc9623b2db95d28d76886f4ddb20aafa1f9c291bbd150b605655682d03cc55e1172f15b68e4849c4030cb5cb64c47c8e412079692" },
                { "km", "6725c2083bb2e2dd5f5fd89425822319bd1e54917ce17f08f6f87ed7bee9986808bc63e142bbafdec35fabcccd3602eae41b0aa8a2ee2fafa37242a127cf3826" },
                { "kn", "5fae5ae72c6a7ec985b1985c91dcd46c4855d48f0a55c96435056ed7fa032cd8c8464f1eed356bef8758147a1876c6e6e62b4208cbe7babd755710287fa84c22" },
                { "ko", "8265063e0fd0281ae6fc767dab9a1a3c7ae940513452ef983c66336dec75a6b5c388b30bd1ccb7b5ebe4528bd8b08b55581a4f0eed4e9e7b5835ca14b9523b89" },
                { "lij", "6a01cce499739a47847dcdf24238649138ec41bc88ac38327af3b10f472719947eee2cbf0afaee2af2da2be9a7b61a474a3f11e4ad0a04eb2e7e923485bd5369" },
                { "lt", "2da945a58d4b1002bc0a43dcf09a7a3a159e2380f637bc65d746b8cf820873f023e1c1683a2a306e12abc425079a81ae622d0121ca684ecd8c5a8b933e8c7296" },
                { "lv", "17cd95f160f63e742c2e5a23c9840b4c51c78a389c20e13ac7dae94ad66c8e78eb8ae3f4f12fcb06a60efa3c54d5438fc05bc9b2acabeb37184ecc6260551152" },
                { "mk", "783943e961827c15be5bd95a4a7eac063537cc50fc56eb3d09586e222c6126274be5bdea7d37c276e6eb85960ded351baa5c85a23ef54ed9e841545cc18dd2a7" },
                { "mr", "6449da7f03167608bc5085f6c10458a1f19709a3d286a710b368c181abfd63ebacf8bd847f4ce07f6571215f1c4dcf6a667a44eda0a9386b1aa977976c37e386" },
                { "ms", "5f84ea4182080b26915552b4a0ec061692408b7cb037f1cc96a39673c16b83726641b912a7ccb6c47b87be21304212e4003f1d72b43c5f7b563370a4c9a98fe0" },
                { "my", "12a64be0f742e6e4689d117d36abfd623f91d09b5dd4d0b00533f9e57e982b774644502492605f8be002b86a8f2cd7aba0d91c444c47e545a8336f0229c51118" },
                { "nb-NO", "1bb3c28ae46defb3eaf3d685ace60260f5f3984e70f2af8f178db859f01a7b2b8508a490e93c85a833cb213f0131fb2422253bec493fef782ebb7a2bdb22b041" },
                { "ne-NP", "75410aca6b6bf4212a176e29bd36dce97610738d3db3d64b2b018ad03606e3a65286e528854e3b551d3b12d6ae099b9cb651c327de44d4d68fdf2127120e3c24" },
                { "nl", "c14ce85940ed630ca6a153b1c1d709c8efaf2bee1391554bc17452acc8b26186fb3236ad7f3fda51f32e8578b62838dc115457a523a75e385cb915563ee93696" },
                { "nn-NO", "301e7e7f85a1317a276cb49593bea0eff2e70def01f0369539c115ade0d05501e8ba56f45b3ec64e5bed54786c1065520b9953fcc25563002f75da0a1e78484c" },
                { "oc", "a621da57528f403d27a6449864efbeeb9d231c9a6930620009798bf0eaa24dac35f94311747ea141e3e820537d2dc9bc578e4b2f5957e5a64810443fcb9ddb49" },
                { "pa-IN", "240b9c373e2e4e0d684e477833b297526e49120c76533c55a6347e2e893bd59a0de255d122cb41c4cffcc91601423011baf9d01e1c12900177f062eea6a35209" },
                { "pl", "f0158f657138e36e2e1b0b3a2b1d8f72ee44244e88493123e1d8587e1928504476dfcd7e8d0cc17855065fa209b1786070ffb99ff8da88eba5f314eb41428dc5" },
                { "pt-BR", "f1b75f1128846a9b57fa390bbcc723ec8fbd80c62411ed2025e54f8417e38b3a2c5fe70e68cc58ab858593ead2a4465a1ac4e755466de385fb41f84a51b173f1" },
                { "pt-PT", "8a415a5bbaa3761f3f0fd0f30599cc2755e514a35804c9235ec116c0a3a5c45791f8b4a5459a62e6008b1c03b925d000b63287856ef9e3b86a77329fe0b15b59" },
                { "rm", "7811367310b4c75fa85b82f0d33cb420d791a908397a00305f3f67326bb675421bcf65a59a0ca3f7d281f5e5fcbc4b0c01ef4f23ebb6f0efd3a7b393b158f349" },
                { "ro", "b49ce8cbb3ed8f41fff5c0437de70093ebc2483ee742f63205e66cd62924eade69432aa0cc403430d0fb3d001d1c50c9bc2829142a47b863bd7de0d56ac4b1d5" },
                { "ru", "36a3f90beabd32abba0ae23afb211544456ecf8d817599ed9edf222e6d9f7f906feb76b7b70989a3e2b44ceb418814eddf393189ec399bb9b2b2e8313c9ee795" },
                { "sat", "51e81e2faa5f79eb97a7f1d1eb3cdfbab8171b63dc53cd758caedb117878fdff99195dc567257fe4868aac9abefe1aa6a44cf2b09923e0082bcc6ce6cad1eaa0" },
                { "sc", "dfe9307f76fd10ac20499cefe85694cba1a0910a8c558f2b6ae7f1a74032fea2ed1c30bcf6d50bee35f4a57d2a6eba4d25504c9bcbbab032a80153475f4e03d6" },
                { "sco", "d2f4d37f6b384d93d7555dc880bb673a5d522718e45701265c455cff66841486207de894dc8790f9678b63a403ec0ad93de9901a904fdacec5574d6525c379ec" },
                { "si", "f29f6056e100f90c8bf3fd2eb575d77dbd9d9a0f66ce11797c249b36475cec7ed87bc16fb551aee9ef6910994ce622c6839e152da8333c999905748cfc3abec7" },
                { "sk", "bd663eeb2e14b0872e0a40e430c45ed8a30ad04fcb2777b997d300116594bcccb1eb22fa3351cb290a0b954701a68ec1a467132a6d2070e58de4fb21705edafb" },
                { "skr", "bc4a9eb5215145f4c0b89af5c3d8eb8402820157348f3d2e58242ef7b452d23b2d24a447eeebd57c60bedae03cb635e905a4a8f7e139d6fefb62677c6d359f9c" },
                { "sl", "0670d653e2eaa7b583af1b47c6f2c57c54f5955d38c8b92935f05190924f318d5da827b10b33b414f329084b5b11425a6da1d0bdeb47c4af8076997b27a3c1e2" },
                { "son", "a2453f71e61a4090a59fe3b23858a441aa1cb49e141f7592b211ccce6d99c8d6d0395a14eb9a42c172597034915b27d431406aa7ce6cefe13f6c4191fd4516c4" },
                { "sq", "e1ceb4c27f031f654a3b9648d819d7b6d49434194054d1b434fe0590edddf73043574378f6b9038f2b5955ad095caabd5058f9403c3cb726d42342edb9a0cac8" },
                { "sr", "948a0fb83fcdb2a151b6aa5c69c75ad160349db5f7d7355e2301ba1d7a2365b2498aa585e979738923eed1b15d66f2724f031d777106ec63ff51f544373ed04a" },
                { "sv-SE", "ddaccf747e95547f8adbafe71873b9a00c2f33d5c7859bf3c5af5cb6a2387257e50b08d3c69b48580f7c9b9edaddcdc694e191693486f35b16c3aa05e4698090" },
                { "szl", "dda75a77e35dcf7cceee86d6aacdff2f576464034d170b12a226383c2f9d218173a6f30639a365cae478bc6ccf861fd9855077f53caeb5d4e4fc3d72e66d86bc" },
                { "ta", "fa1f9eb4634fe25852ed09fd84c3bc6de9565918ccd3e49a8721012eaaa0889700bce27eaa069691156e381b52a99f3e8bcf33b7bc2ba8d1636358355a85b572" },
                { "te", "f8d62ba9ae7db643edd0f2944c81a4ea4e94cf26d008216ab3e3933b309804d450211eb4859e5f5f17354d6796f602142f4bef9fd5774d33689cb9ab6380b4bb" },
                { "tg", "b89e7515b641da4d49e3c891c7f69325d042c4f02c9761a080f2a281f266f89aa36cf86675bcb667290204776a3e46c934f3c9cd104c3760f92812c5fe022d07" },
                { "th", "2af46179c50cc8345d75da38d11add55f4b94c83ea0fb21165eb115c4a26b6716e15e15ce82f7b67f7cef43573f16eb6567c6c34ff8e243cd49ec1af2d0748ea" },
                { "tl", "576d2d4846f08f6a9a4fea609d7d1832453b64edc88c33038588d97f9eb1cc72fc5ae122c5abc1a77a507c239d66eab9a8a8edec02c2b2a037ccafdfd6b263bf" },
                { "tr", "eee8d56b9732e3a14fc321f4f0aafdeb6ab6c4568c49efb7761b801ee6ddde4b2d53fbfc0109570a6a74979e21b6d0cb9e6190bd115d9d628de6040e2651ccb2" },
                { "trs", "17a02635779fa61c6dd2b0ddb85390024c09b9225b2bdcf6fa1793180a30cec48f4ea070e272963d3c8e307fcab7ed783fbe62361bf86d0506e48e625981aef8" },
                { "uk", "5cdba838575549e67b67bf6af292227eb13e3e16a382cb43927cc1b34a5639722d804bebf5c5eb148391ddf7f9ae9a05c53703d144d1b3e0c8a96ecf402f187c" },
                { "ur", "1018646f8e7e7fd663b2c829c6c55e9baf77e469f06a3f1291709ea1de18637341f9c8fb940669fd5ea0391a3004d90629d8cd79c6edff6ef433c4b527b77439" },
                { "uz", "821230a8c574b3b661fd433f3d6be46f8ec71cd6d49a43b600172c66a541bbd75312a9ecbb2588d1413388cf731bc59c8c71f0bf5be58ef0f530b242162cbb3d" },
                { "vi", "cf8af1c9abcf9a7fea7d04061c1af43689307989c070942e983a1cb2d40943131b9f4e4907ef2535b9b62b91467ea81f53b76772ff22934991abe1933a5fb45a" },
                { "xh", "238009b0a5c8fb87f2a7d2118a5d2b8215642280b1833ba857db39ca3917d22b5df0275c15fc82df63eedbe2e33743ededc0c8a289b4f395dfb7524c74692d70" },
                { "zh-CN", "aa30e6ce35c2d4038a2f3385c7309bff2ef134282b0a84746015033cd9b3ad411b3371995a38f530c1b7fd31d8b558aff38cbba28dccf13a05bc3a9c361b06ed" },
                { "zh-TW", "facb452b9985f37b118e97cf052b0fe156dadbeff161b65a70e76e91e98ec6307c11de9c55f79b9850dad1427115459c4361e98b773521b8a95afbdae48fe456" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/144.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f7240bfa93c46b23e44b9ad8dd7332438001c1a6273c6058ec85ecfa801c6b5fc0183c29f6ea190cde63a3b7f8cd46c7e2859df0398931b442fee76d236f5900" },
                { "af", "3e152a375706684a076fc2925e0fcf923a779f525f5971350487a55310ece15dc3ee2b2dd75b1ae92e023b57ed9c58701ea7ef68a0f3e90970b16ca2ef87544c" },
                { "an", "5b21c0c2536617072a3b63ec8e08742a0e1f361687f315368a7868eb382b5a16ef7973ccaa34659d5472fe8aeb9295d14184a891c450db6f4fc4a65754e07a4e" },
                { "ar", "63c7532a5c111cb2a503c64d780989a22ac39236bbcb8ce7486cdde1ad0983d3fa6224531d0616066bfd71d765eac50d2f94e39f90cbf0207e9e1eec2c835437" },
                { "ast", "8a0ed25da756795c5cc28d4a8431aa1d2d4f29aa232f1780df5b6e84804995e088094c73582cf6a26b787263d9bbe03011afe50e345cca18240bcbe6869bea64" },
                { "az", "8a9eb84bb3b970f39820beeea004579cc715e5730705235229657d324e22d942b6d36884b5210d63c9087ab24cba9e2a596212eaf8828019fa36b6cf7583a724" },
                { "be", "a6f8298604b53d2eddd5a970d7fc99f46dc6fcf8ddddceb84f52e33f69694aa4001a63dd9bea9287768db5f148ba891f110274fd45f499cfce879c1e90601e1d" },
                { "bg", "8415e25b8be4515c5f1db617bacca971b66451042199ec0efb54154187cfe5e977ebe98330839c8853296c33c289ab8a00fd0a564799699a9a244a533f74cbbb" },
                { "bn", "0df42f81d063d11195efed11f554018e71b93cfa85ec9591b68ceb15a1954de142ee7fbb4ef4ccb7488de0f590d72472ebb5350899dd2cc5b170976014812197" },
                { "br", "a21ae8d92c2945b364fe1a0ae230234f6f4b7256f7b00c85b270ee46911e4834ea4f6eb0a9dd8523d8b31ca0b75599bb1408c0be48136fc6d1153e9cd22b0196" },
                { "bs", "7bf78d18e500569126e900941ff55d6e6c34ae1b1efca452142d777a2b26b985d1053673b174987d6dc0939676ef85eb69ce099109830c2a108ec2bdf8f25778" },
                { "ca", "0b95545a791d33d93b8c32a9609aba7bd306e3ff56f197a207f4251143474ebe16a2085118fa18c2c242a92206b90ba97c7700cd20312eee4f528bd68014c019" },
                { "cak", "9b40f31a544199d9d15e74014f3f43349f9398cf9dd373284927e3f8397b04d886582fb195166d94f24300c69a8c99b8cdf4f7cc289f68946e0be0ea64c34114" },
                { "cs", "9dc32d019448efa619e35ea2f36e9629751d6f05f6814d6f14e654f9750d57a97c9761b0635be702e6ca0ba1b7f29fdd169ca1462ec9248fd8debcb10d413681" },
                { "cy", "6f073aed726cb3e60746ac24e82f5f60f72d41d96f2450a9fdba82c91862fd4e72ca9bc84d84150d2b13af0d67fe6e52b1ea494069e99fe43824c8980a4c275f" },
                { "da", "d8dc8641dfea69b5a5e854b00ee4733afd8c863fd2b2a73ea5308d3aaf4680d23cc8042600d2e9c7e908b833f3b8c04a9372557b7109f064827092707a4cbec0" },
                { "de", "5f79cb4255f5b018e6b415b85affc8adebcf4e635260bf931c635743fdd9981bb6f52287bddc07e2bb5be999bcd5e32aa53b5090228967a07f2d6c07250d6556" },
                { "dsb", "623e5cc33a2d2cbd40b2bf952faf9d62473f97d1564e7c2c1161df8b0f33b9e6c0faf91b0c851ad70b5312478ca1102e134f7bd342d6335941d2def3102f668d" },
                { "el", "703076044518fc4abeee6ae0331f39abb6f508c68fc8eff1f4de6db3ba269d4c5317e504fe521e9be1f8fef618e558f96b6072ece4e0af93b69f5a05aab41449" },
                { "en-CA", "a04ff9c047d1f782ea14982c33e2d3e4a60cffc44ca38cb574dd99769678de001266213b1596b2dcc9e39cac4b73a4931b4c238229d0b30c4b8b79e762af7cd3" },
                { "en-GB", "741d2227321891b62211856bffe330a42c9245a41d45c8a5b6cfa0ddee3aef1085050a9a53f80a127e1aea6c1eafc81513ae2cc53b48636fd8349c45129523c4" },
                { "en-US", "b37baff8ae9487bf7b1c7af6d2f2ac28616354002b5f23c43324dce10a1519d10ee243d231760d47c8bf1d6f6d17b3dc5b1b8f2ecc5d6839ebb71ae46cfa0ae2" },
                { "eo", "f72a43d55214aeaa347518cf629a71a433b2984d21907df147bbc63293a70494efe7a99bda7fae69228107c5c3821425d6eb351102a3a46c9d3235bf6676a508" },
                { "es-AR", "5df3ae0d40197f8a1e6e49ea351004d6402ca51e8c3014a1247b71b5f0a43fb3bcda781b216d52e27ad45cc5857bf56576a568a323db6607d143c7fd731ba9f7" },
                { "es-CL", "0d3ba7434dbf484976d8eaa41c1338fe11ae5498c0d72bcd9ea4fa273a38e847b22f4012e64f44e6a75339e673fb8258f48f8b2b3dd09d993fd6382b59a06ad3" },
                { "es-ES", "87de403bc2d34ad4cdecf67967a4b88c9a1156d682a1ede2bfbe1adfc73efa6eacb0e06ab1e6d6141a26112ed7e4d43a7cab5522cda4bda96e6259c3f57a3248" },
                { "es-MX", "755687f01d51f176c5eb7fe314a7d0e8642f73210b916074151dd4f8f3383a2131a2381b3cd2271dd876f77f49d3590774ebfb62fc5d2d8522835735f903aa82" },
                { "et", "4e91dc8cd0a7f219e57db73c12a5819af9a0ec7c70cd61ca588b5eff8b2dc69eeaf0e990070ad408022f6041642ab6a85a83af4508f3876ce4d5cd3d5d4151a5" },
                { "eu", "ae5557ef245332906f30a2c1ea40e70f99a34f987ca33f99635dce92d2880a0bbe8f058db32c8ffb45488f204ca5321e12a760d252d68541913882530bcbbe9a" },
                { "fa", "4e712a9fbdb1e7e2c6727867f5f0a9d9e26e95af12c039598571cde21eebbe964e31db9f0952627844411eff9911329f62c35b868e2bc8d59a036432d604f45c" },
                { "ff", "bbacf5558ab46b8629e3776e3b372996deddbee24e41c3b1285e6dfbbb9cc863863f6d869e5e98e5139764586342485dd35b882c93f4bed0e74c81c9b3e8557e" },
                { "fi", "004035c5dc06ebe6625e30372290202ea4e61b566f5b9013ee6a0b36c113fec42185359bcd75701cc9f1812ea2941551a88d4b90e4b92511de29fbe4099f2028" },
                { "fr", "bcc43dbb4a7eb63f3bd8220c516608ffc53e9be512d70118b0093b706991115e21a4644cb71f6a3db299e9ce31be1203b7559b1560baaaa7aa7aae636f79dd3f" },
                { "fur", "2c396b9d6804e1b51cfa57565f4c63ef3c9b0eed5cc3e685bb3bbf801b29ea17f1b69f2b3de6fb7b2e2ae79f5b889700750f8852befddce6eb883f414917da70" },
                { "fy-NL", "5566ff21da9cc58dab911a4dd5e832cab85a55e1946fdb8c02b423e883578acbdb64769a377ee1c6b05ac3fa6707a809a6cf58bd13775f8db277ab843f51d449" },
                { "ga-IE", "4e164589b55fbaf64d0df53377253777ac787fe38602c9531084c7194b70e4a9971b3adb18faf80cb5f746f3d5b7e022caebca839eb0fc337b05357b277ced31" },
                { "gd", "1922233579db37da1c877331c5020f32a6f2341043101284e366faa532c3fe7ec434855622ae2ae75c52ff34ac6411292701b7be6389a83b4fd1537c7a3d0806" },
                { "gl", "3b3ea6f8ff93e370f5803b7428548bf7ff6c40d5f5c5aa2b25738a1c4f458dc9ea07399275c189fdf42aa0a79b06fc88183c93b9fc793dcdeb8da7524e284bc3" },
                { "gn", "a47ecca7277b93a5fc6c87c010e74b492a77a804ea6b8fbb2626fb81e40d38baf0da6b10c5dd6258bdc12b6d534c1acf5057a653dfcfc5eda4a1c863bb0b90ed" },
                { "gu-IN", "d4bc275fe1e7b4b45451671bc014a697e4e0a5d7afe9048adab4d090ea50a4724544c3f58e51096e391b9e9056f0c8a4f426a7b296a25fb9b6559feb4855e12d" },
                { "he", "a91d5aa5c8c9470ca2a8a0d44421347c992d84e0cb9fc88c252793c275703cf8c1fd3e7e8913e64881b4bbc8162a7217e00ecce391931986ec0128cda14aa974" },
                { "hi-IN", "195753b3768f58af4ae191e2b5af7acd712f4984e81ab381c7e35c0ef02b89f03fc12a36c6c3d528c890e19a66a68d8b181b32bb272878fd6cfa9de22f452628" },
                { "hr", "4603b0361c16f9c7e33917a0ef44dd84e42c3173686d2c9e467484286f02ee62f59e264887055b6cb99d40588dce449f7552bb481907e392ab4cc0427b8fa9e7" },
                { "hsb", "684e02299d8289a403ab3c3429098f438d039cf72f72856903234f190e596126f2c58371961bb9e3b0751ab3975c9fbd53a1c66997ea2246591e422a0b1552f2" },
                { "hu", "92921eaab952f075df93c2478be4bdbe912ef39be4a6563c2585c0fff64104f605ff96be4a310a22a7c4f3fb048113c1f23d2c1fb953c18d0e6213ff88bd4501" },
                { "hy-AM", "818cedaddb2488615e06a1ca78ca424cdbce5b2730221ae1c3a6b44d6b9a7e47642e701bad1a4db0f164db2b219562db21f6b0ed338f3846efad6b4a998f9e40" },
                { "ia", "dd02017b3ec7ab388679be0d786d8fcba3f12d6ad6e1f473759612fac152eca79198f055ea7620fa17baf20d0dd079ca9e1bad7c3368d8984d905b08267c5879" },
                { "id", "729e11b44a7b6cf325e2d0c00f504294ff153c390fb1c06a5426e063e44e7f66f0a1a33ce003ab42996d0e28681d205702debb69a93d57bfaa3495f07cd003ef" },
                { "is", "f12deb11dffe349030b37933e2b75f8ad8d9147e34352b412727c8f94fee2bb82b1bb3077e3e252b97bdc188daadbf9cefd3388084f61a85d0d491094ae47005" },
                { "it", "366fb7899d7ef9d99e6f74f1452c5845b2b609e47984d2eeb13809e56dc1ce4600b00695baf4a0bb22f2acd6eb2ee905c03b11a1ffb63bbe0bef4990ec90be48" },
                { "ja", "e637d292afffad566eb49e9181337d587de6acf4b02af26ec32c5ee94af421d007912f7b767144c1004d199cf05973098bf40234cb50af08413ec78276265542" },
                { "ka", "f804fba03c90f66ee262ca5495506a89f715140d2a0fc3826b96ac30d24d77adf245d0744a998d02bbc58a8a102c1f663df888eea879136e49d6c43e61041b7f" },
                { "kab", "293864a67c44a0b53f016739762a32d2a61a6ed1e73497839135277da54c9b30b16aa2f23ba27128eade5c1f0e0a46295a58ba2cc0ddbd7d1dfdf342e457e428" },
                { "kk", "00a90a651089e0fa149ab147a963a0bd0100408d4d1f5f5fce894c1fee9497d3e62e95b785a4794b03cccf0c9f1ce74a67873b1e2ebefb0e91e6a2f64d933ddb" },
                { "km", "99dd5aff10e1ce576ce8573666e208b6bab3fa8a04a7f4202fbf929662f00fb6c28db45dfd11eb63dbde204c1f90d86d9d4bb6ea5906e8dd141d25fb722e8ef1" },
                { "kn", "90c6506715660f966447bfb1f027044c9d02ebd99c951d29b0e0c98b2b3868916d314d2cddd5b4ea7e12adf9fd91acf921d1addae379962019512837fb2a8e21" },
                { "ko", "bc7f1ef6209be80a51c015bdeac2fe12dbef419022e0044e2d9348152e430cd345381fdc6f9681f88dca3ea440810a3aece4a1456c75f27d8c4a400d53904865" },
                { "lij", "32c532d2211cffa578cf0f0784cf6bd0336c48a00f5d10e636bce9d38e39e3b052d0b7e0b2a9b87f8f1ff59fbc71c0766ca25fe81beba6beeb18215c8994c158" },
                { "lt", "79771bd1e6107f07d8f8524567287041f4255c7f5750791c4902dccf0c2340807d734a1ebc3b92451fa986a1f94637297b93b4384fba9ea475f22b1f0ea0faf1" },
                { "lv", "bb09b8a5b7a69c8c0ed6b60324a20ca0d0697c3357af17f3f0ec0f634224365c0a0be996f803ccaf08a18fb776584f783318ffc131ce998d6d8ce45b4e07ce3a" },
                { "mk", "7c584ed9ff5d3fcd738c586816d5bc79fd341801f00edf7c15c5ee724717c53f580250d76a82bcbb09f4a1def4cfbec09ccf9a97a074c5643a30b3e4f7935ca2" },
                { "mr", "e91399330caa359d97f681c55644140dc7faae64756ed8a753554e351db5fce82b39cdfc3f637f3d70109e4430372718f67fae5817398307814ed20b6b860cdf" },
                { "ms", "d29f70f416dd05351d9e1876852f0ded93adfadb92221ef637276e6fefc4c3592cf70dbdd260c58d3113107de8c96745f477f8fa0fb4abbca36937e4a65d2fd9" },
                { "my", "8915aef8c6e85b0a286b937b76ac7cc0ff248ca9adc930790bf778189d2659774ee0d081ebaab6ff27be2b0ff64d12608ca443b0caf27bc3550a4e0510258a90" },
                { "nb-NO", "bde565b69b0dc80d543109df20f4af709ffe452de412db4c9a837e3092cf7f49bdc6dcafd3fea5fba93f3f01d50e267a52798c5f6b14ea6182d460a89edf1c96" },
                { "ne-NP", "eb05e214a49c96eb0877a99f9425ba8a059a45001204583cd6a25b21df18fad42374a6a29410ff93ed56fbaebe129c439fd46a947b0a3d63936a9d7833fc081f" },
                { "nl", "5e2aaea5e4d165d98b9c29eac05cd2e27edc5893969859c5a4ade3b0b1103dfc8aea237df2d3a5b27671c8244ea869e4cb7ab1627c0d7068258a2300e77106d1" },
                { "nn-NO", "57c9e2c9e18807e191c327df97f5ebf762a0fd6d52e5c312a3d2729e385ed79b334d3b1c85b86592d0b23a27fa54e9e49e6bbf225afd0857b1ca01465d3e547b" },
                { "oc", "e12f7c91d74b35048bb6955856f5873be834301d9fccbb4520c624da212f8af3e72b4251637bc4530def74f61b6641df721bc7aac2fe409c9347bcd53c1a2cdb" },
                { "pa-IN", "aa838aa59a25ef6cbbb40c943a81a0fde2ae326ca420be05deab28a1453de8a92ebee28d360decf1b69c8a8d732e4e7a5338e462ee8b1ca3affb37d4d6ff2a58" },
                { "pl", "6cf27acc78ee4298cce98ee71f6917314a7e33056244df76d02accab08e359e31b80ce6b4d785100ca04608fc9844a4f84e5975916c86d7f3fd9917a22e6668d" },
                { "pt-BR", "a49c62d84c576530bf9ed9943a3607f9ac510e7bd845f66a934c1d6a59ed7499132fc94bc94f548a778fa475070d3599ba77c10302728fa84e801d59dd14be16" },
                { "pt-PT", "b46fceac66153f9be1e5ef52d4c4adad22987055f0a902cf98ef45830100d2d352cc17927b9716446c6af3e5dbd7f0e3573e707350f776bc3077ac67f008bcba" },
                { "rm", "38efd7425316dc6ee569ff9e0056b86013d584f09c783a918094ae682b52af2bdf8622bd9f005d23700d8cf854652b429dfcdd16ecdd3a4666da1d5735883c6f" },
                { "ro", "8156a5c6216320b87b30ad1b4e1530d29387c6a92cee4de5f8d1e6164f2c6cdcf5f2846bea3f0c99534dffeb644c6bff5036a2eb69a3f98bb1af5b51f819afcc" },
                { "ru", "40c62ecc72e51c6d82a4e3f48046be0ab48d989e160c22134649077ce0e5a8352896075925b9f4107f3bcff95e91aeef250fdde90d59290aa550a129c97f2bbf" },
                { "sat", "7d91e6a9c5f22f5418648beb89ecc821a093ea41e5ac7f7345b1444cc0730f5749ac78be6dd087a47b91b7d5d8614c3253b3b88d1599690e1ba587ef5071af51" },
                { "sc", "cef12a9a44565043c4db3d9be4f8eb3b134467fc10047b5d11baab7bc302c3d7132bafc8cd24d89c7026a4eedcaf595306b0c8bee38e4bb746dd4cf7be3e1684" },
                { "sco", "51ba744a77b718c955225d9c5f4be98d5d8c717036dada8d35d83171ccb5f7149182bdcbba7529429b66be3577666842fa11235965b35b57e0a23b4146b64cab" },
                { "si", "06499633c3170153d1076a6545db9faf1fea7fe4042bddb16d5826dfba0c70491181da878c14ac5588073c155a6cc6585bb6d0314aefd99a3b27a4e68f4f7009" },
                { "sk", "e0f4bc4c4ef9ddeaeddb3f127098ffc45d8befe384f0088171b30d19f33288a305a6bafffe7efcf8c30be53b10f287d8be6fbd3627432e53ff076f087af36053" },
                { "skr", "cee2b997bdceeef90074fa674fcadc665b65959338ecc8012a316010c6ff97c689dd47d443ed62bd754f0922cf41ed21cfd3e56f0cd0d36aea8f101e25bcdf09" },
                { "sl", "e6cbeece4ed1198eff0de1c3d4c2bf47ed4f1c2e4d78f85d83d104c02eb4cdfff3c07fd4334592e71113bf3b364a51d680e774be2c730c0c8fa56b21fa8ce062" },
                { "son", "9cc9ff1a7693a6f92e0794c1ed759c619cd1c5bff1c4f58345274a11b0f44885aa7c1dce696d429f3493b4ec05951f69698ea4c26385bd43ce032da73d07b161" },
                { "sq", "6f289327357645e8f18703145ac060c851850afeec0237697cc16568654baeaeec8b7f0a97e65da3726b0d67f158e14a283712db3b3c465672ae4548ccaf46c8" },
                { "sr", "2059a7a7e5d155bed5fcb790c5900d8d96cf40f75b98981fc5bfdeb7e998800736d95130d885cf3f5a83e6a8e6353eda9237f8c5d7c234c7a5a5bcf2ac111566" },
                { "sv-SE", "09810a4e93a5dae9dc983c182f6749ae153e82835ba719582923c705c5951f4f7d9f4f157a7321cdce74ee5a809d2bf9d6db186593911b2e12168f8ff99c33b5" },
                { "szl", "66c788f159bec151eb08b8c2b0ac49f9df79fea442c5f3ccf902b2106c1c24b71609beafeeffea3cd9351945b8df7aadf790df9589f8551fdb73c99eb3e91831" },
                { "ta", "0e92a39b50ad0753c8f8f99756d5d9096c2b2cc7fc0ba045d83ea197ec15dcfc582d0b8dffc8e0dafebc7a7ab82dee90fedf182550600008977cbd77b98fe8cd" },
                { "te", "5294f16842a912281ba5842e58f849e1f9e8e496a9d0c7d022dc2218d125d63abbe42b070146ee0992e81af64239e04b15c8ef14c9dc44b0b59cc7450c2f57ab" },
                { "tg", "28afbc31987abae4f28b0c452385f0cc4cd7340b56ce4c0510f3fd1ef8c5355088aca345341b8f4ba0dfe3d9d9f345db8f92ae9800440cff8ef7c5fb01d240e8" },
                { "th", "64a14a15cbf3016ff0eecfeaaa7b15afc9f98f49956f030bce710cb1f0cf5e5a1f7516f6ebaed91e4fd008b9f29f2fec84e5f0f1d24b8f4085b0f6c0919782ed" },
                { "tl", "f4363363f0c52f9a935f784c796d5471d8bbb5a5a44026adb4b3cd1010558969b358a4b84ac6bcc4ba27ab1e9bf8ba5a4b385cb0735b5c6d41ab1b4451d57636" },
                { "tr", "e34335ef8286f7690d5a91e2f08fa57922ce4447d8c6677e75411fb43a39bbf38094fb2560bf2874d160920825eb987f94dc575e51659aed48487368956244c1" },
                { "trs", "8c8c13f58e37e21e9090d00be2583fff8d7fcd7b0914efadfdbc57cad1426498b7018cb6bf4340c9d4d80f66ec9618734558824e04e47c533082e9e02f503e03" },
                { "uk", "d18c1e4027049688254ec038faa8d5c846cce4f95973a503f19e058b37a91a668d992dca334ecf7c5abf845eff0a32d4ea3be85478ffa0ca7369f8334386b4d1" },
                { "ur", "896d7ad29607eefd273db2b7a07bb401b97936c1ef99ee5506d897ed767418729c571338b2dacb71ddca20d75b62fc132c3f04cee43b75a86f5a621732a7b015" },
                { "uz", "605fa7cee36bf57d0c75928d6dec27bc33555ee7df9ae13d73ca8bb5e6f240c4c98e6b498e165325ca2b1d6406463eabc316f5f570bbbf447fe835c00568f5a2" },
                { "vi", "96e7358d0ccfcd608e5d2df63f462a7f42b11be8e325590c97b065bad32ffc9970ce1e68d6ca9b3edd585dba53afea79f28452e4202a6fd9b1de1124113c4072" },
                { "xh", "fdd5820c31135cb5de877d4001965152f4ce9fa1e4bfc2e0af218d943ce1eaa6b05777ac91faf296f0b8c569f4cf2be38b2594fc2521952800f660e60e7a3d6f" },
                { "zh-CN", "88eeb8214f1ef2744efd63121b457cceb93d89c16c1e493053ced1aa7c5e02b141be8f477fdb051cc590473e0d635b90d4e2525573532268fe8c793c55f608aa" },
                { "zh-TW", "f75b3820649461ffa0e4112a3dba716dd2ab1689919a1c1d75f8ef4768cfeea3892ecf7ac27a757ff7302db0ed2e1f4eb5cd88ae0af2349beb541c23bfa2d761" }
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
