/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020  Dirk Stolle

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
using System.Net;
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
        private static NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxAurora).FullName);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "80.0b8";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
            }
            //Do not set checksum explicitly, because aurora releases change too often.
            // Instead we try to get them on demand, when needed.
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
            // https://ftp.mozilla.org/pub/devedition/releases/80.0b8/SHA512SUMS
            var result = new Dictionary<string, string>();

            result.Add("ach", "4e28daad4058c97ceafa85c7694c3a39e9a5f68124dbfdd1e10fcb71c6fa1841cff28c3817ce20441ecbe934d80c5f4a196602abdc705ec74de35c860cf964c0");
            result.Add("af", "e2aa260843fe20ca1765deb83419d714bde48da04fb8eb1ec0a0464883a866e41386506af9a9fbe8140e1c616a4ecf7e98c1e60cabbb80b9f50365a6fe8159df");
            result.Add("an", "d30a5a123e14ed1ea2104cc8a5eb656e156b141cbd65203cc48971dd41bc563e5623ad179811be8fd7954ccb94c130b67196fed79d61f2ff95f56893a8c4f416");
            result.Add("ar", "540be3ea7bbebd97f2c461d342b95f77bd5baa761ab934ea019f9c314da0c71de53db577e0ed35f67891cb735bc46d89305a5936a1f8e102ba87c7a750b285e7");
            result.Add("ast", "6a15c0834a30a375bb428dbcc94d423d3ee3900435ee8538eb4cbcec5d1551e374c43f993b8e27bbac91ada8be86f7068c00264411abfe965332a06d8f57069b");
            result.Add("az", "605328f9c5e042bb2867810ebbf85627b67ae35f8715cc6aee3ef4835769b2cd70b5d93d3d4f739264a2bc2cb8a8f3e7a9dc59bba27efc202220467ddc252b15");
            result.Add("be", "4126e57ffa4bd052fbe12a69045f80c24e905fb5f26f5342b8c87c210c972f01a32c18271b170fb605cb9946b11355b5eb4cd99dec6115a266e10c57fd975f82");
            result.Add("bg", "f961e19d61be009acda3fca86aa510d11ac9ae346dbf03c835e1a9ccf37243a0f35a62eb2f96b67fed4c0e48d5f4d731ae24a45c9aefde5056dfc5eff7b306ff");
            result.Add("bn", "8a50a3b930c0579acaed78a56a5e4eabbd4d7b3c118b6b2460351794db25c3e1b3d28a70c103b80ad3d5680921286163fed370e4620246804a1be2a6d8192340");
            result.Add("br", "da183a1bd3a5e28ec40b604250f9d2a043251e2a674feba6a1bf54085c05d3351b2bc9814aeb18bcb99651039f74a6d16cab526f0386609114f6d6f30cdb80a7");
            result.Add("bs", "4e8b4e5bcf9ddfa1cf4b8fa4f850b1a6f1163836a7d56de2e5ba2f34e007126de8f2b99d2dedce3d67c2dbc2c6c72d8eb5529a2f66e13e49514952007468b396");
            result.Add("ca", "6d1cb3a6c837ea97f62d942a7317749368ae2680a1abc26a3a26fea96381775366b9c50a90a9d30f1f5aff1cb177ea6fb1b530dc4f0ff447f0dfee96f68bab5a");
            result.Add("cak", "1ec7f25e81a1de31e7a474c9844f6245ebc3380ad432f3ad28173b14c521ac2ca6906fd52b2a4200d9c89c741185a785790d0baf1f58a6d97f8256e7b5a97e65");
            result.Add("cs", "7538138535de3c9248bc24ecb129e534066cfba51891af919ea53fcc0203fae109a1cee694297245589cb528f12674056dcd6a5ce397888c1f41c2abfe1ee587");
            result.Add("cy", "74d81fdefcad6677443892be7910f387f6ab45a914f58d9a664e2524ad776776e5acbc5250966569b86ebdb3aa31031d7026ead459da3edecb0e35f57b790560");
            result.Add("da", "2b3866cf5c4714ef21eed8787b319433ac678babe7c03d78f85748797289e8440e0885c14084457c51151b76b1bf640a7317feb02f1a2a23992e9dec5418cc22");
            result.Add("de", "04ce2cc32b54674bb2b15d44a18ccafb762e729de2172c2a1cb11fbb3042d732c71846fda9f2bdf9182741b3ec37696cf6f1d90fde9949d730edd2999f86d37a");
            result.Add("dsb", "15524e73530bbfb9fd440a360662af8c260f823555c4847e10e9821e041ac37d8e2d3d4ab392c3ab2e21548f634b9bcf85992e5effac788748d0a0ef41404621");
            result.Add("el", "5563793918bb4e7a066975d26a5a48278fc4d02d55d6ee3160370fcbc06f3e63c83a859114d537b27ac7eced0d0d7292fa7fed657f4561d4e80d457de61cee48");
            result.Add("en-CA", "a07698364e5d484a1ca9c254b7ce6d533fb97d78ee32eab76d28b4dbbfb65309374a9103bdf2ef1f527b1ff41d0f27fb6eac2114b318d655314bad08d3548cae");
            result.Add("en-GB", "03969d15306b49142d880adc7120166524415420f1a32094e8661ac5c86d3f1d5d9dc8523fda54dca43db12f065af91ad1867cc500c04bfa19ab588273e7ce32");
            result.Add("en-US", "d50cdf8bd857968ab4825c8270769139fa22a05c6f7d22314a4cbe79e1c709b8ee32edadbdfe4e7bf515a4f05dc1250d73232129258463f09b5039315dd6477d");
            result.Add("eo", "367467a7e725a231010234b26ee3c3b4429744c1e7183a743725ff3d92602a1f135d9e40bfd78b211f5072a0ea20c5e6c72ec896d246993b57d3f5c405a5d348");
            result.Add("es-AR", "8bcd434ca26d50e5e56d20142f1c3e21184343bf1252519754615aad11aa2a663d1b8ff939da39eb41118c3674f5cf7e4339a9573264aaa9ccd9b194d1f40fe6");
            result.Add("es-CL", "70bbae14701cdcab40a0bfff46913cd946d2018731fb0a9782ba01cef21861e3d1b1e69dbc5827fa390bd1d56dc0b705d643379710831079b487be5dce0adfa2");
            result.Add("es-ES", "b31dc0c59c074f683f3e0a722f23126c936dbe4e7ff2437d748ebe2eebfd9bb0094cff5eb89ad3bf0e10d1c40950b874b8dd0d1bddb31061923b0089e6dece41");
            result.Add("es-MX", "526a85c25a967e8f2f2b9867e06b8057c3acb51a48802ba460efa3d18ace382350a8afc4492aa6f4fbe9a81b51246d6235875b8a1f8458b9e153e05d2a9dc883");
            result.Add("et", "cb714c91d7fb04bbb9851c153c8f561570cff579495b6a7c3d7bd587677d07118ccb55273b6f7ea29724da5c6f38cf602794494f15fabad49b9cc855222bba57");
            result.Add("eu", "558ba4929bbead356344721cef2886ddb12ec1190443408043e05d0ee07a0ad34783211d732ad3fc8f99931c4a8039a88fb015ebbd6bd6d61b2bf0880f5c5872");
            result.Add("fa", "71cdc7d454b710a59db72f56d1edfe5d5ca11f625fa999c3b044045a6e10d11f4dab9de003ebef5588196ca85dbf056176b8870f10f4f64f50f71f0eff356134");
            result.Add("ff", "5cd34470b3f7b1115e9662115f0a2a74ce6ac2857ce1188cb8dac5fd7c93e43d1f46cea8e685058c7adc56fd7c4bee69da753c24c339fa3803f23ac99ca54679");
            result.Add("fi", "fa9d2dcd61a04b4258789ceb936baf073fdfa6a485d0c67cdc4b13378a246f3f2d6d634cd0617888442f0cef7ed7c61d8af525ddad60a607a6abbc6467ee4841");
            result.Add("fr", "d3f4b0f99d2b209c68484a4cb9bc176311c0a6ce94355a3e213ee72834653369a9c6d0f932f51e17d4b8d4897ea560db8d58e2ee47be0a7b1102ec7d93f38257");
            result.Add("fy-NL", "20be1086c8b2c19804694203a6b9a7ce6573570280d68301fed9316c08b4a8348d9e0453ef02dd1d3a4ab8c98ecb332fefb8f4eb0c630ea77c7953e6e6856e9e");
            result.Add("ga-IE", "ac97391bb52dfd5c7f7a6a9fc143e5f48d4e77020bbc407df80b63ff6414288a839d505b7000f19eeb24ad8f3281e267a1f213b3c2cb904dfb8bbde6bec87ded");
            result.Add("gd", "b6e9dc0187a01440f3ba3a6503d819763c819d5ed87e99d1ffc90ee3ec05ca720c48678199c0cea409856ed67ceaf910befc03348f90ad02bfb257e4a2b5390f");
            result.Add("gl", "35bfe524d9aab5abc5f6b149c17f0713e0395c76d71d234991322c49efc6a8ad5a5f744a5014d4a11be503dec6323a5d85d51a1fd74e4f47b775131dea14f3ab");
            result.Add("gn", "8bf8ec583fa728a69e81c33cf089e7c1816dfc2d0f5c424ba2e686b40d9f5e8ebb5544ee0cc8eb02d3c110ac7b674fe306d8db55fd9ff77e56a3937afb512554");
            result.Add("gu-IN", "b1e3d6a336d15e1a761fbb0191bd5054f51c14e06e1707d503465e5a1300e0644c0081ecf2c4c9e86b3b4eccab92d69a985db760856a3cce4504a4d10d5599e5");
            result.Add("he", "ed3cbcc86f24a9276827f36fba6119c2dfb738fc60aedb4dc3c7694173ff42a090ef25f8f4987564a535b41d035ef4ce1e0f188cfa89951e6c4c58af64c81f9e");
            result.Add("hi-IN", "0489f87856577a585a4067d1b0470c1db2eda0a6cdd8bbbb7c00215b0adb7635fb5cccf2824bc040707fda0483e6c6e86cff8aeb8aff4b6c64787474c0848683");
            result.Add("hr", "b2a48b20dd0df8399163dc04fe1700e0b0c8d84a394278f3f7a01a2022d633b059c035f13d2a66e7548c0834ac593f816025a3a8563b695c66ad785fa1e8e9ce");
            result.Add("hsb", "d615a2fdc4d21def6376f0fbfce3076500a788d6106eb180a03fb30cd37224f3819129035932eecda2f852fdf801bc54c5135cfa1569c7156c5a7f94ddc257b3");
            result.Add("hu", "72301fb5ba90e786cae4c641c40e43c09af3cc6c69d2f3e79e4ef4a4d3e5588f70aeae11898311ee6af5efdeee58cd17c8ccfcbfcd44989c7ef7f9caddf0d18f");
            result.Add("hy-AM", "1ffc356f654e040359eec8e8ca5dfeed073686df3ba8d3dc310e0cd48f39119a19834075820fce21e2a6fad40e68c4657226a711d9e306f3ac1c6dc3713cff3b");
            result.Add("ia", "3be290306ea6fcaf0c6d87786a2f4e2f7ed8308ba48478c1e1ded5fc9ea5eb1533726937f8a6fb237df8d98661bb1f23d1a183a79c9e6f2a64b539f0cb941915");
            result.Add("id", "a3bc6f3849714826ae60bb3a177a5f1570fc848437054188cb28bbc84d875a07fd8a6bca135efc8e524d977d6c020cb7682ae0190fbf7c8d0fc8744bfebb4173");
            result.Add("is", "3faab2179c323be0a31325d04b4a3292a13f57f337d668b9051bcf54dd19ce46e33b438bae6384b8fe5539c9d935a676c982888ad0fd679c5b48aa8d606d3def");
            result.Add("it", "fd12039cb8a13d651479f4c1c995e9aae5344ba09e690bef586b7e27e7e4e16fcbb2e61ae6d062d2637bfd710ad62cc6b32b34e32e62fba686a4fce9d081086d");
            result.Add("ja", "d56335dfc2caa02783b556e846498deefd3a447de0178150db97fec8b15b9675d144506e83c9aac35dd62b173cc4298a8d2de05f1f4b96e51443cbf7dd18b1d2");
            result.Add("ka", "2b43bd9f543b7a4cb892d9a58080c5990b41eaebddd4bd19d55b8ba190c92f05b6363020e4009af5e19b5c71845ddf600bdb4b49299f7e8d8d79575a011b6bda");
            result.Add("kab", "e800c54947ce0dd9ce5b073d662b4876c20daa51a219b4e5c8ff993ed8e231b66c17ddd17778d779212850a6589229dcde772e36245cafd24426210982d286eb");
            result.Add("kk", "76fefebca2ec979e34801b6fc62d9a247565aa8e15964e3d8a26f676d34918111776f4f1c0e9ee04a07c7df4c69642e87488437baaea34f5d87998161634fa4c");
            result.Add("km", "7c407b90f790438e74b0a59953fe92ecbdbd667e19314784dfa804cf59dd2eed185f1c1018e2a8548cc179ec5f528541e6b666846af9daacbd2f075077265cae");
            result.Add("kn", "6ed7a2624cb4973c70fbce170aabc84afbe001e369437ec751e3ce8f748b16c46264906d918a574edee4cfb5cc9f9fd20588a97be3b9508e5528a86c39f1d044");
            result.Add("ko", "1a77743219ad8ea1e67a983d6933cae27b7aaf30f8aa490d9bb08e70b05f59cc80e72b9e8cf3812af3640209eaaafe568c1702c0ca6a676f61abca640445ed2b");
            result.Add("lij", "82cc3db7f227f3e81c584aa2f506ac51c51b6f24363c9d40249a457e15c8ffd79e799df1b1160e0036183ed7ed0ffed40246d6af2e5fa9203e2a4c82768ce0d7");
            result.Add("lt", "d411ee2341692946ef345a13988334ba03494db179619a3ccbe937faa93e2e4b92c6dd9547a4d98b8cb9cf9252cf4161778f3f057434a4d08cff8673f91a9232");
            result.Add("lv", "78699658cc421e300242e43c2c65ee39a7fec65e4debb5a589be104b8e5603b2e5079a403834349e1a54e7d03d992e4b47476bb0c822ea8d1ae24b91f736c332");
            result.Add("mk", "bf9c5f0205edff20a52b8cd34e40cb645302b4f26d1f86fd90daecb66d2d6612b3b133204472d4ba30ecb361d9ebf796f59dd96f8048f6f966882e41e45b2b3b");
            result.Add("mr", "df9f7d306c25c63dcbbe879da13d994ddf950714b04e4709f27e4308544dadc7cf7013d97795dd6b527e36ab311a08387db1424f17423f998c811cf9f787f4c4");
            result.Add("ms", "ff04185a6e76b4e1d53d0d89d9d97d3e4918a0b8f66199759c34a44db8dbac3e660b906109fd72d3e2d322ea28c94310c0edda25458abfb121c071e9f0e14861");
            result.Add("my", "37ee859064eef79f15c413ea058ce04f56132b6128124c89d207c119640330b2d1bce9323a8dbf2f782a739c61241978af4db1a07714e189d2b6f3e2f637e602");
            result.Add("nb-NO", "f0ec0c1c960977f2e64d5254a82e8eaf4f81665d2a389a8a1e0288cd01a8c4c15927e2fef038663962be51a6e751e185e716c99b08680e8d8ab7a9b2454f789c");
            result.Add("ne-NP", "9edc5b9a4c22821bc21e05ffde609438aa239e80c92f02e4221bb7f959c1aba775050f8ba4193851dbdeae153d063c84206f65ebf77cb3ef8d489c00c105efb1");
            result.Add("nl", "5aa8b7027555ab646cc8d76f85a2638af2c23850afd6d63af94f3b99b5f2dc2195663edf7acdb125865b81bdd6c5c8a41b1920258ba9a71298ceb2089d8e00e6");
            result.Add("nn-NO", "c057bd7591cf9aa1a3ca92a38c23f6dc74c487e7b0b18132f86a0b635161b3e36a5d38ea7027493a58eb1f9ea5a52bfcf93957baaf534980ab2f0d0115b4edbe");
            result.Add("oc", "6db87a8c83cde843f276b1bbb6c52b2ebe946377e92a431417211b2dd735c497aea115fac724b8d27f0f419f6fdf1779b1485526d18f1c98769b8f93ae99cfc0");
            result.Add("pa-IN", "b12660cd3b8da6b1e11b1c3539b97e8389b366b486db6d185cf4c4b4a03ac215157fc18af24d3f64a5619d74e3e93ad86b00df63c37139f0143bc4e2fdd1752d");
            result.Add("pl", "1c02448de9b0cf585de02b850e889ed1e1197a3de59e4eac524c3fa826b4c538041837dbb1a4b5534c36776746b7a10e1da6f092a759b6c2898798e93faa4489");
            result.Add("pt-BR", "e12e502949bdc290c641a44478636bd13cb2fc1b5a0f4c45df054ad0257df8ebe0dcfa13551b75fdf8e27141289825043e109cc95dfa7050499be156f79456b3");
            result.Add("pt-PT", "6edf81021671178fadd558a20ab7bd5a5672da9ac7428721d810062a9add31035e00c164d02f0abc2467e82a19a0a4b893658118f23b01c480c433adddbe0580");
            result.Add("rm", "9c4287bc22f6d45936c15a6f4468b8a186c79e3318fd2d0ddf0b5e2ae38f035a333a45f359fe00578f81fa4739374ad5184d02874b79575920b143e85b066a24");
            result.Add("ro", "2ffd54987bd96606c487c0eb7b0a6275dca13dda73dac02297f8fdd6c98331557d56d3a45710ecadd7be13e007795c2c57905c3d519a3d7c9c9510c943800872");
            result.Add("ru", "cfd8d4ee0008ab12e6a66531efe3264ad4fbec2ce0d76a53cd2a2091bddb7b24de88a4b4ccc3b397ae5c450649edabaf26271f00a25f5bf9f58ba4d995e81363");
            result.Add("si", "57317ad2f47f3072d20192bf12f5c8988185c54ccdabe3830c3dd0c25c78d6f51d94f8a3f0fca6e8e6f35ba2c0de4e2abc11627574fb254d4ea3f0020fb9995b");
            result.Add("sk", "5f5586b7d58b5ffc1943550874f07763181fb84b095a407d25904dbd7f4d8e371174ca4acaf6af2c872f79c0a4a5066d370eef3ac7a4d1dab557b66d665640a6");
            result.Add("sl", "d2de64d1e46c74860cb6c0d6f1e2cf6faf5228d53cc4f42b92bd20b9beb04400eabfe0ab19c6cb767233b11a251d5bcf1975a0d268ab6a2777543c1a94018f5f");
            result.Add("son", "7d54acada884d9015e0affe88f6af5725efa2fcc3671935c9652169fe94c9d8475bd411726d3aafc43bfa11a69de331cedf0eae0b6cddcd4ee082b549b143226");
            result.Add("sq", "f6ebccd5fc8709c5d21af72dff87024b9ac4d88da3c18d7f7e386dda9ab49f7e1f695180bf3b77bc08ae4fcdc9881475ab0e320d3e3b3018057d6b3441103a11");
            result.Add("sr", "8eade42fa4970641d62969388e0a32e7147f02401b3993a63c602cec6aa566e9a2efdea0a3c383b78d9096dddd512781c908ecd1e9116a55d3003f173df462fe");
            result.Add("sv-SE", "9389d12ab94f8db66ca42118c1f7ea65b66d363a9da970ebfbdb6887845b8aa16f247889f5e5a5dfea16fb9306cfed70f0abc6bb6825f61c517596ab5dca5f89");
            result.Add("ta", "b615f2da7b70aa274bb7e1de865b8bc1e73f08fce88c19209abde7c6b768ba2b248426106c0f0200bd2c471c41b68dd0c5b717c9e274a4de81fe64c6928b51a5");
            result.Add("te", "d3bfe4a0c5ae6e36b4e536d4c4942194f1dc3f9e2085a6de228bcbdb2a47aea898fb1d974b26ded684bf40ba1995912f2bb9d25fcd3420d503eb67a252b9ee20");
            result.Add("th", "b6fbf6409c3f4f346757f885c4204e091e9f3b57c5043ca41ab9d58964982c1536e9c0909d84fc72ecfa54f8ac04548eddcbb50a11e3068de5b6b895aa686db8");
            result.Add("tl", "5c0229486716115bf5ff9ffe63940f589a76bff44ed5f4657725e5f02dff1c8f3733226533b2dbdc647ca16f82482788169db04067a778db2cda6cccab7235b5");
            result.Add("tr", "d3c822f85d031f4e2b404d0d8c27cfaf0212ca04d6b197319035b3e2096ded775ad9d3fad06961f19cd5d7c24ea5b9a72897357852110b9d00a09de3960c7de9");
            result.Add("trs", "4920cc424cacf8dbeecbb12080513424c1731bf50d6a1dc33624e0dcfd3ce20f658fd66f537fd797afc4f7b43a49dd5ae74ee722dd34d334eaa983b8548e0b20");
            result.Add("uk", "69d0fc93c31440a240f276f9bf8dfcc9d7ccce46add46b99e9b4247ce66d7064a3510234ee2a853b323047286ec76e44fb5574e0ab466081ff46cced4b941964");
            result.Add("ur", "315045d1b978ac719e4aa3c68509ba01dd4b972699dc9e2d058341b7f4743a75c4078afc285edd93e954e833885652304ec7efe6a12d06548d5e760f767bf215");
            result.Add("uz", "52e596e74b943ed7e7699e2d748dc73dbb2168eea78960f624f43ef08575917eb2098094a80958e1c886a68f0f19c8a1aa9caa26b2629997db3eff5f462a8e0c");
            result.Add("vi", "bbc9b7fda155d7d80dfcf94cd9d1297fa14a1ddb96817863b68dd633cf8bd43b24a7022dd9550f3a33b3b67c82ed5908b461c071ecc9fd1f04aab0968b158478");
            result.Add("xh", "6a246e38c5ac75110d8024233ecbfbbf3cb19820b4303bfd28861222ab4366863e55da2970d40bd82c177138656e79224702eb0db7b774f3b444b8454a76497c");
            result.Add("zh-CN", "97d607cf5ea20a22f44134e467cf5ed3fdd0c51d5b4710dba38efbff0a0fdba9b3cd0c7e0e154e357d936a22c7df0bc7c16dc69979086f24060315f92fe0b4a0");
            result.Add("zh-TW", "9d53c5929d56022c0abb2c8f54b65d8e8ba191f3aa9a2ab1482e62f8e901ab68558050aced504120490be1c5540a111a84d9366dfaa90d12d43926cb6a3cfd13");

            return result;
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/80.0b8/SHA512SUMS
            var result = new Dictionary<string, string>();
            result.Add("ach", "1a6c2d2e54500ed70284d03ec61b0e4c701aaec7d7c68feab127616afd2bf5d3e62daaff3a0159dd939358ae822340b1877cf1dbd517eff5406f36a1bae6d6f9");
            result.Add("af", "d30eded71eb31c81811d55dbb9b78502cf5bab5d546c3bd4652a65035a86f96fd5e8bf1cb1f50242ec91f2930d4c8789c8a792d41569b038b507cdcc0b38eb4b");
            result.Add("an", "eca9551fa1927ff51d81ec896df9251b5f8f8b90f87c7c1dccf64ac2298305ebb3bc5efcedf08713ede7f8be90f4725108a0df585ce9b21b1668581831075fad");
            result.Add("ar", "39348e5a7f5a0d2ddd0fd60216ae60748b093166ac5ee64363f332d3cbe38e5ac86d09134d1e3f79ce668e4f2837705b56a5751573850a324516b6de29d447c8");
            result.Add("ast", "9cb2725a2afc6b781e935cc14b2965de9bdfc8f2766196c989b18133fb28f6c3cb5f209758f2aa3f256255dbd29c0710f7599c2db063d3fb75e839c86c98d546");
            result.Add("az", "9302e23125f8fbcd008fa3754f995e319c181ab217e73da066e7281ef0969feafec00d6565a31b43b365577e05c64d3dd09bd1a264e2c4ddbf8d7553b37fe92f");
            result.Add("be", "7375c94ee7ddaebbd005f84217b1182180b72110a64e640cb0fd049e61147b864df014c409bd114ab2d486297f49afd26fc69c9ffc8e49df27da01753b5cf73b");
            result.Add("bg", "2f1e2aa742bba0ff18ced39fd1a5f5c6068d98238e48a5af7e8090c4fcb876db851bba87001d5cb03e6831d531fde1c2588110127ac9d0fb245fe40b53ce9e0e");
            result.Add("bn", "f7c892c6f9d654f80fbf6663fc1087905631238bd7ae20af5734a797acdbddff644f10a144834c10a8715d70f88a63c6da6464fa134808fbaa83cdf489eb92b0");
            result.Add("br", "c5e30ae9baec4efca18c783a409d7405ac7c1d941946e8c0d5775c41f1913bb8ab370af7ab9a57152778aa0ba2d28544e172cd45f6cddadf22208c2067e8143d");
            result.Add("bs", "48e666764e8259362017f884b2ddd8a0c97cb94e56ef26b39c146651e36ddf4ad47a152c57ba3cda81a453202bf763f9a53f59a3082d5dac39cdda7a390b9835");
            result.Add("ca", "94ab965d344d488d28b0f5723752083e2d8d113e84e7ff43d9ccda59669d92909b2edfa86f55d1952a75267435be0180d8d7fdc6e9500f360d9db235e9b3ea19");
            result.Add("cak", "7f3e1031e8ec99d18a028fecf594bfc63597ab90daa8d9199d4df6e2148d01a6024ac28e43d9b93a6d946181629f70b42533c75c57257d1a9ce035fd747b06d4");
            result.Add("cs", "bf86fba2fe6d058b09323522799ea5998f969c8919721e9d479477871d4920bd7f8c8461313a18ec24d17641c054fc7cb6d422b80a0961af02b04e8cffc8266e");
            result.Add("cy", "fbf26e653a7beadeaaabffd219975d00b5b9aa4adaf346cfe4429ac2c0cfd5ed14cd9f01f67e8340731aa46619d604a5ba44bfa00fc838dd4bab8aca024853f9");
            result.Add("da", "42d05f0ba6f60066bee52aa0f3679db3cd0756894658f7271cf2bcdea7bfe21bd125023aca260058a14371b51a73a45877b86dab0da9194b53611664127f2326");
            result.Add("de", "67bd85f87fe0b3121d7f1b5eb7f48a8f70a17db8f411b6b906765c9b365e0eb9b1984ea6cc4244109ca8adcb5b0a83bedecd6c93c8961aa7150418ea9cfca12d");
            result.Add("dsb", "39bf7c042da0ae8c8b2e163f05a01f27e5e768eb012a0c1292249d63130849d97d76d7b95a07e16de1acf18ab0f58626bdf4690353c563ae79aff704219a5ec2");
            result.Add("el", "1f72ef677cab9c71ce288965aca50d687f30f23f88798e557ea570943a04f6d6f74ee0624a299af38944d1244f2665060930a18584fefb53dcc3d956ea931f31");
            result.Add("en-CA", "5cc54ab91b97ac334b7c7a0dfbfda4ee067d326be8be148a68768a2a11506f0ed8f540573d90b15be254e9a3b844f8b93f9f880f4c8220b9c6af724d03b78d6d");
            result.Add("en-GB", "16d835c0f7cd3ee1dd702c845ca8500671545c4f548861af899f051cf4296d4cbbdf0e1776a05fafa48b562426f35733f52848a03b2658e50d68f679d2e1f252");
            result.Add("en-US", "9955cf94aa4d6bac0cd775dd76870fcb0e6ad0155a12bb0affd6b5cd286972ab15c61abbdbee84a3daad4e778c722d8bf2040c9d20c80c7fbb30d5588d3548a7");
            result.Add("eo", "f121bdf12bf95905eaa3950c59fa8786c97716ec4f3a75324187f48b6b711ccec4f74f5f171d2fcd30ee61710426b8eefbbcf3cef8e097b5f84b5b11955b5ad5");
            result.Add("es-AR", "2c0a3a086cfbb38cb70f483ec5f7495ae72e79b71de10ab30caf19ae6a8e6d7e1d52bcc4a5363f96aeaeeb47de6974417ca6719e4a8256ddd0c390a689fe1b28");
            result.Add("es-CL", "922041c45f9bd5ecb3dd9317a2aa32443a17e2e9b81009ce8ce3782af33738250aa7f6343c5fd4e9e57390ca2cc3f6fee1962bfc96a612ff69c994b05ba1c2bd");
            result.Add("es-ES", "1a0bc381015fdb01a40e3f1789d25faeebee4e10b956ad3945bfc1f24c42f7049a6874078cb1c68cca2847d1a093848404738683e6e4ea65cc799a5854256d36");
            result.Add("es-MX", "0655dd2672462804f099756b2d3ea2996d22d15aedcfe1e0ac201b693392331d0134f8a47bf54946ac362c08c635c24880d34ffe903457dafa8e826fd732b01e");
            result.Add("et", "1025cd9210650c8219a17d296bd672a6dd3dfeb906900d589ad26b8aa75a74a68d5ecaf37df6ccc8eb76077b4c66c5fdfaf2da5647be2bac688bb4d0a35c2b4e");
            result.Add("eu", "255e5966cf45b5fbdd0d5b48ed8dfd51871910a2b42230a77c1c2403263c055634fbe9d4a73f9d9494c31289ea0de18d9ea87c87c6324f28cb25a8f490b34d53");
            result.Add("fa", "98265ee188f53f4f13e329e3204fc94cd17d9cbb1d9a640a10a6ff4befdcab605799f8f380e821dc40d3429154e4950d7fe3212812203a172321389a88ab52c2");
            result.Add("ff", "ac9f6c1dbe20c2a3288158bcfc866cf9d3fa812edeae74e72a3d45273f29a43ed5986a35ab342e9a630f31d1c5f494b7a34213f3d79e65eb30735183cfa29bdd");
            result.Add("fi", "c7bab29f256e88fc016a608f4f98ae6800976b4a63a7e3b060dfbd6b1a03ab2ae856355e90392ce3a5fbbea4b53357899246618b2d8077eb932785861604ec83");
            result.Add("fr", "43b2ea0f959ae053deff271dedd53130234b3facb5f98cdf0ed4d91a911ab6a529ba3faae9886ebfdbed8e278ed836dc1120e8ee9bbc4c03b1a5f18f2a74f060");
            result.Add("fy-NL", "82efc4f010fce43e725ae1b8464fba70c90687edf8a4773b7fc400c946edf8f3a5dcdce95a672cd22d2376ab5950a363177424594ef8014d87de95422278b208");
            result.Add("ga-IE", "21f3249440531c967e0acf81d69b20b061cdafa5042277ee201dd5318f29022a489f963b000f53e697191ce39444f1682ecc02076d7d5db83c5246b1570d6660");
            result.Add("gd", "fa6366c5d0b8415f5233a52d10396ab1f26c1d1824080168ea021e278d5f26836052246ecdc1000869673159cc8af3239faae4c7e68115e19ca04859a2575373");
            result.Add("gl", "64bbca937e446a566d8f4aa095917bb0854be217bd8a3abe030ff82be0029eab5f4b0ec2e63859958ccffa9e0433e6ba9fe4dc577360f8749b53c499925e9225");
            result.Add("gn", "1155e01fb1f4f752ead50e2ff021820e6a30c6047c244c4eaa8557be0711630bba5b84104fc2a926c4dba21b011bb9478cd9198ecc9d26924152623fbc2219fb");
            result.Add("gu-IN", "a91d4679312bdc93f449d7ae55a06e182dbb48e7e09bc11926a5bbb8f585287ce4c9a1344ec07e644807cb4dba613e933f8318dc79ff27fa97e9095e40a3776c");
            result.Add("he", "668444f7269d5cebd1972bf96489ebcb2b818fcf1c96090cfeceefb8c8a1e503fdfa8f12816873cfc78b4396abaaf25db68e552b7679a71b518fb6d3a3c29ad2");
            result.Add("hi-IN", "04ef678ed2e66de0b8a02d2ba9db9d248e47056070b7b33097a0b9fab76a35a5e7d49ce29d81a1e8239ac0dbce7eba55bb0ad25d6739c73c73cce89cfdd8fc1b");
            result.Add("hr", "18084ecca16ba1f8a962fb38a26f860ed8f9be8df61e92187355bfcd7d805c34393fd54a4b1aa358c88e51deaf225206d207df9f7d3137e020a0a5dd4c2b77aa");
            result.Add("hsb", "c9c0e9f9b216bd7c77707ef4e4d9d719da1eeaf6ed2c8fb87027a280b630a7e31318a1ed44c7187ff7b7254d148bee2dd7468f10a0f98a47918a3d7da8976443");
            result.Add("hu", "f8bb24d5481c73663b9acbe6b5e754094528d07c43b60def00e8a013af89ac945946b3e7b95268437e71139e76fe17afebd2962e9b2445e0d218ad15b787532f");
            result.Add("hy-AM", "4c5496750e7761d4f0447f3f2b7aaea74d4fe35137b570ace6018430b87cb7da884c889897580ee52e18d1f4667157cfd487d42b47a66a4d129245172d8b8ef1");
            result.Add("ia", "c6173e99d2ed805f55191709adf1030635b7496d97752e96ef27969620914d812a4f51422c9419955bd560476acd7894a3bc831137283a9c019d0d158bb20e67");
            result.Add("id", "7d7b6a88aa9224cd9d912f6eeaba7898c7e0fd01a745a3d17c6d349c835a1ab672bd5088ca39c582941be299468bc6c5a836a043b21bdca2c983cc66022f1744");
            result.Add("is", "5fecc4177179408641f8b3346e816e4dba0da68e4e8f8b61468843ed444aebdcaf227d4e408f59255c09746f9ffd79e788e2f22756abc4e8af2eceab5996e7b9");
            result.Add("it", "73c54206cec6c766e8a1d9ccf53bb691437302c25f4e3719c56e8a219f18e103c78a03c5fb7b8f03840d61be7339d5da35061b12458116dd0fc270c321c4f2ce");
            result.Add("ja", "177e99a7b5701c7e4e81d600a9cff9664f072f362bf63e29e885810b7ff5f6155e91c1268ba5042717472637435afdecb33e7f8fcc006d675accbebb2b335507");
            result.Add("ka", "6b585f2f5b223f34c5eb4b05e31a47809349314f8091b51ec6937c02352d7ba9db2b66cc635065cc241821829ffd4fc439c764964955b3e26cb88acb3480abf2");
            result.Add("kab", "5a1df1f7fce9fba039feca3cd2404c75b2383c5f42388049a65bc6b3d2d61224d102a58db67c640960dfc44328e4ed64f3522df2259aa4d6f5f3cc77a15a1563");
            result.Add("kk", "228e90642a650c4486f8a305d4f6db00316c3091fdf369dd55c1e92e891277e57ff8f4a64d73d42a245f2ec7b42d3ff00192b2c74f19abc071837d834e7344f7");
            result.Add("km", "2b164a3eb17442db8559ba67efd6acb3453dcced152b04e680a2a6197ace7276ee2a358cf6fc4544fb4010c703c86326c4db286e9f8d7704d04ce40dcfc45b4d");
            result.Add("kn", "45b002692a8ae525743fe475beb57eddb465d7527f457575a342d42deba824f6278e0175c141cc922f97b80c5cc1e0f66236858022f0cca6286f4f24ed9e1c97");
            result.Add("ko", "6fbfedd3e8f4958a8d7b587c2ddfa97d59816599c9794d51c8621466473390a76cf099f31edad65ccf377a7c8855f9c7bdf95eda6d0c41737fb165ce0a23dbf4");
            result.Add("lij", "025bb4e3fd09bf426fc5387c0e9cad32e90ac7dc2786b00d9471b72f552386299cc2e86fc1098765082ad39cc7e784aa665645de78d6fcec67083380d5f99269");
            result.Add("lt", "072a031be751e4eb020c89e4f868a637791bbf83c9238526a0f0387533b1f2c6155fc13f0360c3a50c57a6cab16dc5ee3683fd90089b9632ae06a493348b72fb");
            result.Add("lv", "dbdd45ab9b6946684060eb027b54d6c0ef87c7824a9fbb608b5ffa90b33809a4323446d10a09d593702adad5533c36f62e0c9832d55c207dbf9dd9fe523e04d4");
            result.Add("mk", "52500d4ecacc39644b903b9dfff955ff96136ae5662a623af8ce6a8cc51ceacb8f8ea7d29d711bc1aedad7dacb7ae9b7ba7ac60710b7e07e40ec70efb135f492");
            result.Add("mr", "ab4a403a21c662ed62be48d05f1c5532dcfbfc758448d0a599c7092f0471e8615cd6e4108870ede5b4804333b59ea1c071cee90a60c2092725543ac9e1970f64");
            result.Add("ms", "eb2174b3a1da6ee30bc73cd07fe7588812e927d41d921f3406679172cbf82a62d064eee48ac180bb98eadd0b6ee45035f412aedc54337a07f70610c6785e9b93");
            result.Add("my", "b2982c50838fbaa5f8a5085431269129a07dbdd57930edb8cd7bd1d93b055f5430cdeae25eeeb36a4e46e4a9b87a0baec7021dc8bcf2b7e79a31b2154c6a7589");
            result.Add("nb-NO", "872e8b41e6c7f87019d3e7fe05debccd688d016eb668d08b31e4fdf6af12e311f538f213df3fbd20ad13745a6290c1cfcf8995661474e37d3ecb138e68526063");
            result.Add("ne-NP", "f1b95a9218ed7b9dc184a0cc6b8cdabdd4e90d3afe7c0e7103851649b843feab545ab0adcb19e7d409817782aaa58cdc7098513be34391b28eeaf4e35c0f05b6");
            result.Add("nl", "4268f6048152e51c6ec63dae5943d8e68e4a3989fb7dc7c5ff29fb276a0f3119ed71e95e6b6eeb26d4cbe7e61faa841ac36aaecaa6e089f1a4ea92818238547a");
            result.Add("nn-NO", "ae423d635994157562aa56b58e1877cde008ce8734cc48c198bf15915414110a6de978a428bdd6860119a7dd3d1e4a14d8a82eab69f9932dd16dc5643fbcf7e0");
            result.Add("oc", "150aeb48b0ac161c24f34152be309397a91db0d091e855f31155e4a98bb3c2900681e5e8183a6a4bb568fdc786cc7f07cf2f2e8a60fb2e4f3c06deaa3d526008");
            result.Add("pa-IN", "9e821e01ce403dc0bd8dceb59efad2dd11446bab2ec248778c427ac40cd52916888b148fb9e8ca67343576ed7579885ccce51ac8a054c333c763f6bd5e3de795");
            result.Add("pl", "84a4dfa25b05a079ab4214b2fe2d6d92c28e58e6ce405607b8249efaf03cdb71fa7aa856b928ab75009848ce7bc59fdb131eb9e6a2441038cc07aa1889f0b2e3");
            result.Add("pt-BR", "58d93601ea77b9ed468696c69f19a951c0f873f178b2c480ac22a5341575eeb90a542833f1b37f209a652858dd9bf2747e9dd147c8459df87f477e3318cbf0c0");
            result.Add("pt-PT", "a02edc3e2a155c350e9d5fb30c0058c83f9a83e294ce1bca3240ea5ab444d9f7fca9c33632f2e63f8687b726bcb0c130b66fca63f0ff70e1b19de74a3b065203");
            result.Add("rm", "beb58b34646cc113118e9be3821423f0addfab29dfc108599f18da957ccd3dcef5497510b2dad680093b54bb89c6f81539db1bb9bc09d1a8d5d025d5a0ce4e85");
            result.Add("ro", "fd4806146b7354fe884a825d026acef0cbef167277a554f11b2baa9be9c6b8f4e2d791b4e9794227fbb76674bfce7005bcfae9814493c63f716d67e2ba323c68");
            result.Add("ru", "7fcece7b46c4b075c1f2698fa0fb5bf169006a4f7b1e181ef331fd11af9ddcff50961d757f751d73e6f127f94830c2aee417713cd96472f36b4d48bcb3593cc2");
            result.Add("si", "de1554ec913b1305a172713e5f0d8ea4d580349066f842c1fda43a82b08ec77aa04805c8dca14ee06c97f0f33af4bcca2e15bf85ee06d8f7cbc661c3cb6a6151");
            result.Add("sk", "d41e570b0b657074dbfce9626b1ae02da66166aa070225b026a59b8e76a6463ea9596d73ddf2b7bd9a0edddd06bdf734423ed2cea76263b7093e40510e721f7c");
            result.Add("sl", "d26b7779bb1a3d065eb40ba4ccd881114a21e931c3ab01d699f730616a44598644f740cee6fe2c4ad438c4ea47966afa23c9d6b83cde119eb88532dca224bc9d");
            result.Add("son", "d2a66066a7d636c1c7581681d6f510d717bd74b56ddd74cae4f09bffb215beec8a7540c2f1c6ee33847414fa2024f1891f06cdd9b507295734442cfcbaf7b60a");
            result.Add("sq", "163f1094bc1ed161cbae9f2023a016a11dfbab63e7e8b9b4955ebbe23758bb804a871ab46084319604e8aa71f6e1a017828306ae47a2540f834faf513dad2aa1");
            result.Add("sr", "89bc3fef997ce570dedca7c5045cbdad2f6b2dbdf913df84faf7a41eda8fd59d2839cc12dabf396192094f579012f6040dd37ead92c5e81a5537a53a464f37af");
            result.Add("sv-SE", "1480d39b12ec4cf35027e539565a5d782dac268d9202654fb33d1a6f29869c77d5d95d3bdd78539414c1dc5ca9bd31a7ae21bc3c30fd88fd2bc6d0ca0866830b");
            result.Add("ta", "a1549350f75f52cd39790f8b9650ef8592db7bbf4980235b286418b4227ed9b6792be6bacfa0697f0523c1e30f12ea6364113af1e56b577cbe652a1b08067580");
            result.Add("te", "fce8c293e8d2294d35e4c3d0d9a9fecfa80537856625cb9cf2c8f5b6cf3db0b44fd37ce09317b358dfbd502bdc4d758c7d643c110a691073f2a4c7c4840e897a");
            result.Add("th", "ffdac0bdd0e5b6fc474b1618c0e963856ae5892031da66cfccab849ce6bb1a44df73139a08a8d2f20be6bbce18199fc7ea4aeb7719bd0860c888f1021a20532a");
            result.Add("tl", "c1b50a05fec272c4a06276cb805330de6d3e0411f9efebc981f640d8a628c18c6cd7cd7aa6237900384f67845657e8ef06e666cd216a510b08a22375c013ff3a");
            result.Add("tr", "ec99a9a6b428ca0e7b140214a893aeb7ff5a1eb49a9de8626ff15e24584cc12a290ff84a810b3e311fd73595659769ff99a59c9370d5254118b2d2c2b60a81ec");
            result.Add("trs", "3e7ceec5e8916c38df983eec9bacb8661d5705c2c4a68da8fc34e86d47fc32b05d1634e45d23f090095b842de0abf4e0f3c07de56ec3cfaf802b9ed8bac4c2b0");
            result.Add("uk", "23035ff9ae340dabe84b76ceb91056458676e8173b40894650ebb300a9fe800066eb6ad1cecd307bc0e0698e75c003de1b760db9f57bf26b2beb184d3ae078c5");
            result.Add("ur", "9bd54840f1a7a40708bdb72bbc900e8e67d637bc6949abf0e96e947f4a33d20d83a3550a7f13d624650b8b264d614d8844eb4015a0101192a86eaa72d17d7020");
            result.Add("uz", "d912e41e5e070dd68cb82699f0a6c461b69196c74407094d80e1f9e25556c6f3c702232cbecc1131bd8d9ed6481851126afe6a36c67429c06c1c2f9a7c9cd6ee");
            result.Add("vi", "526f96fd013b8409f80a9d6413af1032b2a2ac27c2b97b931c5de6b90ab26cac98c69a4efc1dfd84a623686f737e8d52db39511f397c3f1709d4f3a79c3cf649");
            result.Add("xh", "580d5729828d3f645c2e4c47bc7d1596933b365b1027e31f594ed473bf4012dbde0a465d4c60e32b8bc37008ae16bfb4d8ab9b0512df186fe7bbbcfda278dbd2");
            result.Add("zh-CN", "891291ffe64cfb722de3d31eaa9ec2755cb7780a32c777b8e4626fd1d79386f0088fb8ad56f3a84078d6daf4d61f1ee25c1750fa95fb577678a93f507c97e4b4");
            result.Add("zh-TW", "35919111032de02231be693d1c5608e61a24fc178db8fe687c21c1ceeaeaad4bcbe98e6194c72603d4833da7b07915a5aea70f99ff358df99f35da2ecb770ac2");

            return result;
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
            return new AvailableSoftware("Firefox Developer Edition (" + languageCode + ")",
                currentVersion,
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Firefox Developer Edition [0-9]{2}\\.[0-9]([a-z][0-9])? \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    null,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win64/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    null,
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

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit an 64 bit (in that order), if successfull.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    //look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    } //for
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
            logger.Debug("Searching for newer version of Firefox Developer Edition (" + languageCode + ")...");
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
        /// the application cannot be update while it is running.
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
        private string languageCode;


        /// <summary>
        /// checksum for the 32 bit installer
        /// </summary>
        private string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private string checksum64Bit;


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
