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
            // https://ftp.mozilla.org/pub/firefox/releases/160.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "d08c4038369549dc6ea59b8aa937739e5b2ea29142ce68642a6d033b98ba4ee55835c5feabe2ab1d86c513846f0e56b5fc8f6f548364cb21206dc102e545044d" },
                { "af", "11bd2b77b5056af382c972aa0b4ecded096b79b8f47259b91270eef6f17bb816234d1e1d56ae67d1ea4795f298e38728c8d5d68fd9129442f93518ba97b75c9b" },
                { "an", "96aba41596be83ec0b161e1ae3048c05a062e7470e8c5f64f141cf09d47b400b3ae2376b4be4fa098c14001a5bb55eaa883269db6aa474a4e7b011ce7b79a189" },
                { "ar", "791fba8c5f2b9db5afe4547e831af09e43ee55f28ba5793a95032d60c71e036012cba007b9b1cc424abb53db758325c0fe9cf36b2a14895e71474c1db7c2229b" },
                { "ast", "c373ac2ba899fa1539d5f88f170f3c762ead53fa01bb48eacdcb6caafa33b76011e3baabcad213be4f8edd0046bb0f70455fff688195a48b55e93792e3e6e840" },
                { "az", "73a297603726978a2ddccbee6c000a396551402563571cfcf2603e7fce4c890e434ec622435903fb20d6676589045168ce777caf30a37f91db602504abffa12d" },
                { "be", "67cf965bc3233fdd190fb9a621abfd59c20df0701f38a2e7ebc92d8cf08f8fbe2da0f759de81f1d4a570f5bc504b6229ac0affab48c7508b65d48bcc24ac7a58" },
                { "bg", "8019c2644776cfe1e2113a63f8f7f8b94e3c5774b40eb3a24e21fe1a1a788372ed025947a11f91407840b054870a261f1b1c7d4dc798af5350184bb1fd31ae2d" },
                { "bn", "b732a833e982977f98dbb4cf4242f76175005a7e71d4657a90c2727ccb52174800d923f7ccb47e918fa87cf9d1456a65763b77716bc3b6671c6480037fff59c8" },
                { "br", "28050aacef8b8013ccb83cd0993826d21e6ef5bf59dccdd4b16f94f21cdb00a3b8325ac990e92a87915c3f8c73d17ec3f9a51c736132bd09c1bc7330e36bf77b" },
                { "bs", "20bc86198db63407475a92b966e64ee074588af8777b080da943aff4af47fbab86a2c91b33ccfd7bad5db41e645cff38d154a55fce3c9f61c5470429829661dc" },
                { "ca", "93efd3ad9de27814fb4f56f05f37cfae75e2e0f055246ad37fc2960f4351ec2f3a0f3a9d5e5c032d034be5a31c901a4e0763cf9f529237655129895ce276afc7" },
                { "cak", "6b7675db84f63aab0b1c5948d73dec4ccef07f701ff4db50d26d6d5040fbfca2e373b350014e1792ad7533818283c7337abf9d7cca146acbd38c2ced315c844d" },
                { "cs", "7770aa6552dfb1d89daf801e5bbc695c2367be77673a9817ec551758623d6bfcd2d6db81f5a8abddc66af22aaf7b2a33484555c036730cd39fb994c3cdd8329d" },
                { "cy", "41fd79eebc731f884fea6b0a9032aeeed0fd70e149c592f3b82cb92c75b40d3bba9239357064b15d7394d0ba89276cc619c8357a5057baa842e2b558a0b08f92" },
                { "da", "2484d32e89a8b7ec27f6b4680bb54ee863ec147412a7215caca8b7183383c26e8295479b6905dcde939c4e6e8588b8bd5f9a3f91d7a67d1e9216f04d37d5e194" },
                { "de", "2be4801205917296e824f58dd47ee431b3f88bb577b4df4a3a169af416b261f3d425b44817f80138ab297a42f0b9579cff0daeaa52a01b6dc951b089e29584ae" },
                { "dsb", "c26211855e409c975a7f6f8799a3939209b3c6de8e2be6a24e64a2d97058ebcd80dfd50e6cb2ff2eda1cbc918edf2a145eccf6c3d3278216fd2fa63b5a04dd22" },
                { "el", "a45aae380d5f24706144ff502fb09ccf64ffb0f603de416dc0ce80b408ee0da4a0438b73ab1c90d8f9f2a192f4cbd8224633b9a868adf5b9bb7028e7b102ee51" },
                { "en-CA", "1e473e1f6eed19e0b5bb0126b8c630d1ebeb1fd8a39d0b1cbec04b564595a5279dbd1b5c897d85a96dd17142b35abc5226f12134dcdffffa0c4433f9cfc57971" },
                { "en-GB", "e5fd742d55b12e34f0fbbb5ea176226e7d78170fba8e40f1fb451a8d4e1368e7adb4ccccabb2e1313f1a19667ce789cbe78c7560afd957b8c63fb7eafc15cee0" },
                { "en-US", "db6c8fe8702d7a29787d7ca30437a9c1227159b823e0ed1c6b22b600658991e66e70c1765037c26fc635a022160067dcd7b6ba5a3f3843d63a5c48f62746317b" },
                { "eo", "558d3f708b3ca61725429ca2c54ffd3f32cc861c3e5f5b44ea31803a12c406454438ca312c417c6eafe995f69d99626193da79a495b6e75027d14a10250b5284" },
                { "es-AR", "b3247a2b172d14ba04b5fe6dab832343599174f1667167b46286cb2ef1f2cd064e27d3255c628bb577d103c1172376599b5484f9ab6e83e672faac7994609fa0" },
                { "es-CL", "6cd17e087668f21ce448eb40df144be08f74d7fea2e53bdb12aefb3e49f48c1b353ddbf08c62364d56b47a06eb02f909d934afbaaa5295639d569b482761e9bf" },
                { "es-ES", "9b33fd3da28dd890a20cb417e490a7543f39ce69da0fcc3e18f83476433da8cf9427cc73a79f24e4c07eb9f6f3ae73fee99a7638fc8e02b2e44be7149c5c1f79" },
                { "es-MX", "b45695a7a15bbd89c28b58056cf7f7360d14bd9d22007a8d9cd8544e926d6065ddcdf8c149f3d2f90a6cfe674bf80e08a51bad161b6bb343ef16b23b0c6e81d0" },
                { "et", "bb146959f26fc4151479e931fda81118946ad3c4c9a59a0c9deb756f0120056873608221116da4225215abfeaa76a27746ac854551a2f52cbbac51fd7a0792a4" },
                { "eu", "d3efbba667f02b44bda54cfaf57c6e77e7927085d1553ca78ca0960e03797abb8b96def0375909d86aba7692e5496f14bc5b5006e9640df378a840ffbd03ce1c" },
                { "fa", "6607ffa6e181516c2a9c2911d8772d892083cfb172c814aa0808c94d38da284a71ae279292a9267cdd3ce3a0a23f44e2f55adab54f868724dd16a90757b86cf0" },
                { "ff", "35e5978f7ed73c45266769b4c13452adb075175c31f43767d47fdc875674ff101348decb6f1caad5eedf8b051461ecc0621dc2baf389c7c91c03b143aba59e92" },
                { "fi", "6dd31b5c8c925b375e5c4eac65b4f074177e05c5f16a1be46c13389ced383423f7c91f95d0d5ee1cceea0b60accabdc2f837b7c84f442db4b97d86abd3e24f5e" },
                { "fr", "4378bff8b15270cb6e35b68fcb393dd63ef6fca2f14837371f8d9a62cd99a15a0bd3cb7783cfe8e621e76db89469dcbe8c1a6c9bd444ca48a83c94f1e36a3445" },
                { "fur", "d58986ae4464544696a3692681a6a8b2afa034da0b38cef6cd6a2427c0d2902c23fd967c59c938f26e2716a087d524f7ff8fcc87616ee8c5ba705683e3c952d5" },
                { "fy-NL", "306677dd83bb675a01e3332efe49f3e0688c8423ae1670067cfc1bd9921cc844d69dd837e6b3f29438de04a454e6c247cfe839c08f6908708ea5170d1e541700" },
                { "ga-IE", "27b90938ba4ac6879e079cc2449190332890155bdda1112edc477053930723eaa29fe6054dd1e11943aaec63fc7518ec72db48e58ecc2361f33ea4a13e5dd04b" },
                { "gd", "9c8b14118df93db7660eafd455ff23ad736d5c8a81a5123243a89966d237fda243050d3a3c37ce13c60cd0d7e4b7269fae0668ba10c8a8c16b13f3e527688321" },
                { "gl", "f88144b5f2c352576ff2f0f7f927f3953ad522662e1332fcfc6b45749bbfd8dbd851a528e82710b4d802b86d68e6577776aa3d82b2aa736480efd7693c98c10a" },
                { "gn", "4d117a98d6fe161d06e9c049fcea79fa38abfb654df59a658f3e91b3d81e1c225c59ef9bee346356c0df06a7b23f79513deae6e2ce6b15da98ba86e566abbcf9" },
                { "gu-IN", "805b1c9eccc56abe5b52e651b2d253521d569dbc60e621efaae082daee7f598a5dbbc78a214cc0d4e628131c5b26391802d2c00b71b5b7b821992bb2eaa70a03" },
                { "he", "35f9a9edcb9db396dfed9b0abbb4f83bf991a03af0bc6facc0647848ec38eeebf4f0579245f2a3da45457cc18a34a4974a8641299bc42cc5b67ee0794ef7e628" },
                { "hi-IN", "5df288effc02bdef8e354fdfb990cf503296f869f05d6045ef5fae958f49803f68e421593fac802b3ebee7f06e69cd80ae4f39d69ff4d7138a90098471da35ac" },
                { "hr", "7aff264ae7c56b53fb8a19dfd70b849a484eae13e05d95a9fa3e5d45c10ce27153bc7183e87defac28634b0a32291d4cd010e3759ee7ea5455be9e720703fa43" },
                { "hsb", "4a948cdcbcf8620bbc2dbcbd1cd14faf1423c67f0e3b47e5c4daaefe4bf298b01c99606748dbcf213766ee75c85bbb65181dc1f3d8fb84542bd59ddda4e7ddf4" },
                { "hu", "6e295116b17f47c67f058472aa4cf2cd66172403e7c1266e4df39ffcc45bc5ee8f23e3373a6aacef0481b2e984553ba269a8d00de2dd6995ec2e3bf4f3f0ff58" },
                { "hy-AM", "c5e4b542052e1bc558cb643b4dc73673f833c118351711514bc58cccc223fe4e868d09e2120c8169c248f06d89672bf62d9497eb1f3e02e0fbb9913cba1780d1" },
                { "ia", "f70b1c53c65adf4fd0f49462707e9d48ca84bd06754b07c725b6b59a3c82ae6e4e363694d52ab30a62886e3403bf310116b6b103d31ee6014b3f6c438f760049" },
                { "id", "152a6af301223a4608cc03660ec06c3609921b993732e789c55e2810643e14ef78299495dd066569e59bfaa413e98e51ecec41cebd8b5503902f5fb5f3a9d2c8" },
                { "is", "01c0a03ff152d21a699a148d2da1b13546bf9594fcf930b677b596bd79f2245f643cf87033488d95ca57f6f77b68a3a412eced25787e739551393dedfd8869f3" },
                { "it", "2130fa7b3ed4c3f975054ca4c15409cb62dcaaab85456b53c04fd8f039ebef011b6eaf077b166bd70db64f381a3dd769b2b3b93bf9dd2bfc2d1c0276a5a3e222" },
                { "ja", "422205648d39a54c1fba2a54518356e92329cd7010ce7ae7c1e9004ac47184c206db2636a128bb381902711356f69b09fd61f5b29d916e8f09b767f55f212c41" },
                { "ka", "45147d6e83dd641abb4367337755bd347f1cb54e0a5b7863e65c595a13b988a72adcd0403807382fdefa013e74cebbe3ee424f2ff52f37178ae3837d4748c7dc" },
                { "kab", "d091fb9522e50841d8d52af04d8bfce56c4ec03e7ba60b7207f42561c7d2094835376d6f3fbb38c9119f53b2b028c050fe3196ced9ad74b6c99b21ad1305f2bf" },
                { "kk", "174b7dad40e70959ef1f5debb4de897d143c5389bf0b560408ecc60bf1528cef93ba09f85a625f47c78886150130dd994a08684079d289ae8c58c7a6fc51f7d0" },
                { "km", "45485be5d8e5fbdc2569454c6d118b93c76920f8f96ed6a00027bc71726e102d7cf1687e52b2fa4bd61a1b91e2733fb719a3a36d07d8e96e60da7a6d8250e0d2" },
                { "kn", "eb2e1eef566113c9e802ea05329b4b1a544c3717cef2f567329b4d5b8064d0398e3910fc8fdd6ab17997d1ce66f05850d801404b3b1ff4eeb17e46d316a41b9e" },
                { "ko", "6bf31e758ad3822da1a04478e7f1f5813eb6257a0f1f010269b47a2b81a4ec78e63c516881c807ccf30d7dd59a58434f6d0b93db136f3777a79c5e27683f941a" },
                { "lij", "d6eda17e8a095563ec688cd4ab3e7b1b7ad70465c7a2d40d7b9fd8ded8dbdf71c33ff644da9f7736995d0dab9a64d025cb00a4fbe5b655bcff761bda59158504" },
                { "lt", "cf14323de672b6f20254d10c5b6807f615b42f6167ae5e028eb8f4488a4fff08a3cb4301839a20bb8c7f03a6c06914002b474cb1fba14b461f87547a77fe88e5" },
                { "lv", "aee74d715689abdc14610d8a5662c00905247fe9eee0feb708b1aabcf2ba43a658a55c9d8748cdbf0786da7fd1fe3209ed86ea98bea2ac98a854878b57b4b0cb" },
                { "mk", "eb1db0c2ca6b7aed0a06c2a812bb5a8ae173e93ff89dfc60939a7df31edb0de4db99a55303503c65b74d0848226199af798aca5a79a03a6bda16dc93fb9a2154" },
                { "mr", "e47d9926b5dba09a2d1f252ce66dc941c6099ad29d414cea09db79c46c0859446f93973272ef6bff9fcf1fdb87535f5421787faed78dee1b6c3925e2dd6159d4" },
                { "ms", "bfc99a49be888038a0e7b21e371b75d0dc11d27192f67326a6569b87913c0f34bcb4e5e194e97fd87bfb251f99545740578dbaeadddf1141cbd375045f6e0a03" },
                { "my", "f50bc3997dcc8a8dc34ec161435c1e994045b83fa2ad347c871f2beae135d99d66c3b1b50e6bd8db8b6df30943aff36d9d811baa26068f72c4783dbda6a6b4b6" },
                { "nb-NO", "83a144bbed24dd8617cbad78d216c0746d556dfd87c11dc4d2017b2dbf2b9c852915ece7e335feb0adfe875dabb8616bbfa94af76b366833f3efb2fc77340f4b" },
                { "ne-NP", "e1b730e8a34ee975d86fe549a47a26f1acb2ec8ce1d9e040247aa467e7cd7b4befb3aba13a68efddc37c4a7b0765fa9a1c62240e143bf71c745814f606e75e8b" },
                { "nl", "a3cc611efafbca1a0b04666e1644f4981943cf3f2b78efb093e9466ba764115b6d3973c28c8e8bcfcdad7248355999014d0cd769a4fd819cf56eccf9435de380" },
                { "nn-NO", "9261bf123bf17aa8d6861bd9ce1b1a4f57283688ad41bc83fdd8a5337a96de3015b1386b52a99b4897dc87a8f3d962ce8d4bf49ccfc0d0a43225e9293b9512c3" },
                { "oc", "386c32ae8f3c76670bd7bf7449b57778688a98e59a9f3eca00547bb8c21805b4cb79962b6bab61647aeace58b0b320effb1a9684724dd4b8f5eaaec784bf8d25" },
                { "pa-IN", "0f7482b68ee70b22ae4785a6fadae9af985609de23aed11f8f1fb0f4ad3d5568559043486fbef16aae0c01c52a29156a4fbdb7d2f1c70593aeff14aa7d8d622e" },
                { "pl", "8345f45eec2709001793dedd28fa6129f3d449d07b74b2967bdc5e47cfa5f5157b882582bcb8b48d6d0f5138c12324de0d09fda7f77344c6d468422971401b92" },
                { "pt-BR", "a5cc9e1533f02cc5e96a361c2936e5eaddf5a035963b3784b658cce1b172f16041dac250b7b110a29c159b68036b526e70211045cb579736c8ad002075c23d29" },
                { "pt-PT", "3ce72c7299210ec23059fde6b2c00d317a8003ee83a3886059055c7453c69cbaddeea4d2733a9764de6ab54b7cf2f19d9065524a7089b41bf753a58009ba8d1b" },
                { "rm", "9743b0eccc2d8580d1b674009a3168a2884659c86ee0d2522486a9132b47ec21fb8771a9beb2d35bce8884df93ed143b49cd93aeb0f2eae2c653d58dea4e1850" },
                { "ro", "6ff78c7f6faf7040fc3207a556f4de3784acf0d46afb7e3b8e3a12d785091a0a1d27e4d727c2ac66444a95432ecd03910695bcb834fb81a5b5c7e98f899ca3f7" },
                { "ru", "7edbb282f0a0ba0a6e0f0d89af6d6913d09da6232d7871d7c436f49ad7df7b0cd631d3bb7e042cd857f06adcf4f0b19ed25633813ed80ecb02d19ed9f7ba329d" },
                { "sat", "80d8c60e002862a3041f90ee597691bbdb6ba63a526909bec9f5c82d56670c251040ebd19df20be336cf00e0e45467405f4a377306f197f79458bacd4de4fdbd" },
                { "sc", "37cb81b7ef11d8b3e17232f14d81b56d11885341eb0a45868e083b0295661e5bdfa92d5a4caf9a0b7287d3040e2aae90e07e06599095fcf9053238674097ef87" },
                { "sco", "a7d75208a478a3d4b4637164316d74ab822387725ab41548ae043bee360733e2cd4fe345345bc0cb24765a709a9110fc76f6bf196e5e10b9b062976a17ed3344" },
                { "si", "c02102c997789adca5be653c20b8072f6cca900107df004e595a6b0b520a7bc2471bd435addbaccce58eb79e73c074e95debccedd6e9ff82bee092a8bec093f8" },
                { "sk", "e11c13d6ea67341639159595cb90377f93cd4d207132c222e2ebe37ee86484b908cb16b3d6ccc111bae3d5f7624f8858b019b20d84b6617b09fb3cfabaa5b229" },
                { "skr", "9aa582eb19af7ea4346b4ba71ddd9b631d2914fc70c482c64c118f8b1f9e7d7b118f68f2dbb5fcf75b9d5f40d8fbaa529ff2ad25e1feb5f536c2363c66a5a8f6" },
                { "sl", "4d3443c71e4d220c66d84c919927acc0be9b7b2a7834da3c74d0d550418bbfa5925cd7d22128f77798a814da54497511bab1fb4d1ffa877c3688b0fda3f27209" },
                { "son", "5baf25c27a4eb06a658e7414efea7e70bd0fc93bb58bebaf495711ad760106c5293dffd871116052af611a438ffd2ed391d4dd7292ec5eabe00cf8c5da3f05f8" },
                { "sq", "9dc5870bc5edf5a452b3f264d6c1991f5ae94857b04e24c6210e63208d6a8b20a07f805d00a4d92e417b59a95d1d5b2eb49ab677e993342a260ea17f9e18b9ec" },
                { "sr", "dc7f6a405a6a91cd02e33cac0b7493d5d242e04602ca9ada541f04af1f0ea81df9d13878b6501955593c23990cf380eeede58c7366fd125d9a45451d3c795910" },
                { "sv-SE", "bd772aee4ead849057562a6d7eb761ea7e7ee0858dc5008a74e2dafe0d5b40ac06ea44fab2d110a9e4f45efe4ffd7ee47676f2900b8b4aeeaa1b208d90e63c63" },
                { "szl", "6dcb7012092eba7c494fb17d6a554dda4a49c222c44396d73c797ec55a2117af56ff99851731723863b1f28a87e08c6ba3715350214f3e09ba037a9f0aa2294f" },
                { "ta", "3768923e0da0e4bd86dea937c9ca249732c7fe01f25706df3d6c8ecbc6444322e4da1468f65b13b014074edfa8f3f39541288e2a710c3612cbf881ad2f4ea399" },
                { "te", "1359a462a6cf1c3848687b9a57adbb4a8bd324e4c4511a6dd615425d489dbdfa9eaa684a88695527d7c4765f5ac97960b54e447f9f0bb0363379d4057f9a187a" },
                { "tg", "916bc27638785bd8faab9e9c00c055ab2eb6ba1f7b0ef274444cee352c6294aee4b33eb8eca8c42a0b08199dfe24c97bce2cf93baf0d5b173c614f1e93ce1edf" },
                { "th", "979a659ae59d78e4a5b6e0ad3ead39f2d7df450686067b867448f9ad8f80d5f1237ee4ee784917239006cbe6e413cb14311d473a9775f8cad70b206497fd1532" },
                { "tl", "3fef1d56a9f0c6482f2933ee820a206bd7ad0af33e7d883860fa450d67e3168cd6872d058d478d5b9c026d98b449bf0ad764e3e6f1c81db645c9e8f96f1dee56" },
                { "tr", "9c327d2d3de0f287cd6900bf4125719274d884264ebe1844947234b876b11448d0dbbdb6ff77df12794632eda6fba8b213e183d0b81a0803d390fe880d81edfc" },
                { "trs", "87a474ac2992993e76cd879ded06592d2b6f5a0895d1523074529fbcbe9bac59eac9481b807d03edb53397068e89dc3f7afc7730db35c5f6b526882f1f0ecd01" },
                { "uk", "802aef05476f5aca3bd8f6f3c602a13dd7122c56202f364fa66adc00d9054632e3e0aa581efea37bb51a73cf96ebf8b02d888bb0edbb6d74833fd198a46bdcb8" },
                { "ur", "2983d8a7111834112c310ff8228a73b74057d6e7320dd3d1d46ec28366b048feda5cb294fcb82040ea084067457858ffe89eed170e12ca50f78a7a79f10434c5" },
                { "uz", "d3f1aca654d4de186570932695aeeeecafb68d937d23509bf2fc71957b872dbb88966863b65ff789a0fe6e0f406d09e23fec9b4685d84ab9c1ad7ba200a5c302" },
                { "vi", "a0ca696564c83c0d2b7ff740c86d53282f003c09ef8aba589bb78758684d99d0db6b4f641f8919c3612285e57c17ce28d05b8eae51b8a4066df8fd39142c9b3a" },
                { "xh", "3d0343b88e25084ab0ea36927cb2030863087ec46f330923805217f1e67fa459ea66c7bb61bf44f97d29899bb8572a6cd1b2903a74eef21c3f6d92b155f79671" },
                { "zh-CN", "cb0aad33b1c8d01f0ed2afbe2a0ecfa7158d84a4351c509fe0b0c2e275e1c1b7df4e671862f452952402893ef71dd25c08a1a87f59e50c44afd24d5b417189c3" },
                { "zh-TW", "e0cc1c1304ecfb4d2d88871651b34249e58a09588eb889212f75c747d2000dcfeea74f6bd12d5cf9dd418d743c07350bed7f56c1a048035ca14dc0ab9e8c7fd0" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/160.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9a51da0b97742ecc30e6fd1de018ae88dbc95223de96904a067b3bc79192090f0c50518e362f42778f76b8d03c4911109db950e1d25aa4082b82bda0bdca4e16" },
                { "af", "260452848b2ef4659c4a8219a287c6005b9f5075ae492a0eafd35db9d04ec4546c7e5423cc20578b30cbb178f6a152b53c63e7a4d18d61a5a9d09f1f2bf1846f" },
                { "an", "85c39d06b205215eb2f005c2abe4594cd8aa74dc4b38823cafb3c0938406bb72f57e6ab89c41741f839b79bf02334679126193881ab9fad2ec8091f7ecc4afe9" },
                { "ar", "b3c4626d2f282034cba12d2becb3e53377afd32de79ef9a03c87ef52eabfc1344068300c03e2bc15ddcdec3e428a1ff7162ad136f7e41296fcdb9d27e01e7b4b" },
                { "ast", "5e1e88cc3544c2ceb845146fe3b1103988501b59bcc9c2192533fd4c369413083d1b8c544fa3e0d687c0383ed787d9feb11b0d7b6d4a33aa55ba876a0b378367" },
                { "az", "719b1755322bd2bff6dcccf657825c77aa0c7d96d3099e249c8ab144f208d13890aee762c709db5bb25b0264efdebf68a067bb1e6de957884c5be0a898bbf2ec" },
                { "be", "2f41ccbb33dd4e04e284ccb892a75ff34c4fe52e11e2f263bdd7b1f6b0587575a6b54bc5aa92166bab018a2b4bfac099094c12012fbdd420978f1c0e40c71847" },
                { "bg", "be4a9528f77615ff9783a713f3c981711176fa2b1c907d2d288fb7befe76e3834596a370440dd341c1d100efa8b078ea65c9420375beb45eee99fec1a86062cc" },
                { "bn", "9eea6917d780fd954611a56c1db157946bfebdb27059f3d76a2dec8aed03d45a53a2963a0375ece9e3d54fde10c8a7be1a68cfaf71c8a21c6092bf84df3ecc75" },
                { "br", "ddc9fc46c2626f9346959e42c6a5c9b1ac05e70abf1f688b732d479de907e43042c102b5cf8c94f88ce7debcb021575ab58eef90efae09f154c0ef85828ba755" },
                { "bs", "c0bbd8101e361b5423a49dfa52f45c7c16b626c3c9a2392dcfba05528def93983cbe41043df852b2389f81b0379652ee7b953bb99bf23b005bc981cb8405268d" },
                { "ca", "5c87e30c385d5982c9646353cc09104c56214a947f8b5dd2c167ce13246dc3c049bb3b52548d109192bf699ce1e8004cdfaf53248abfce8fdb473f25f0b73bf4" },
                { "cak", "deb4634f833b6e2910c772391cc5267fc236513ecf01ae6e1d1abd98bdc9754d375161e39ea5197c29d7f826701c3b3c27ac12ccaf6dc6741f655280c1858c98" },
                { "cs", "03005918f77b2409fb567843147d8b9bb03d0b4d1553b69091015fc7e8f48963d41ceb63a5eb514cfe6739ba3dcd262625c9c49114adb0e7d466356451e29f73" },
                { "cy", "227bb0337ff327d28d485cc6dda6d97bc77abbebc557fdf30ca069407e61398c11327852ee813cfabd34909f0964bea23acfe413e5bcd8dbe9ec3f43c5785159" },
                { "da", "25319b65c2a33f986b4237341c1bd417bfc8f87d600b95d12b1bbf467be4b3d86e0e84a39083f37ebdb4727b69eb24dc84b9ee39f238158fded0e667ac51f6db" },
                { "de", "ce0e1b2375e0a2caa7d7cc868e9bee6685b624cbbd94f4e1442217392ff681d985c80b2d4648c47bae11870307d0496ca4d3b0793ed1655d8a1c58833bfc5614" },
                { "dsb", "12868db0599d44ef0f6de9c65199d282f3177a0b687a219f484e30f2af46e1ece4ba8177d25a8b6f6247644f214d140877cb7b705d4f7d5619e491ba9bb1bc97" },
                { "el", "f8fb02c44f764d3c4fd4e58ef1877f4a4cccbdcd2405d418c97b54b55028e167403d47cf43d3999c68917fa6aa6a4bff1daf91c2db4c8bac3c2295629e88eff0" },
                { "en-CA", "146c3a9443fe81904cf87fb4b512f0da9929f093e869b0bea9a1b0920e538d276ed8c262c89cd74b6d9a6b8eb0b4882533702d3411df33523ea1141da53c19b9" },
                { "en-GB", "873d6399f566173557f00902c48c965e537c768322b4159c5983e02151e3955210d54c6e6464a469d5d9a669cf80d0c01df2d3241d56ae572c82a6a41c38f46f" },
                { "en-US", "d8775c051cc5f5330386a002fec915d2d057b33bbf7e19037d9f65f094d651f63e2302ada829a4cede9a05a24c015db4acb4f56a34d4147beada984487e9c53c" },
                { "eo", "aef9126fffa32d94bc624aca3b629afa7b7017b4862b1beab01352467098dd491d91c224a079d7284d13f385f28f2b59bf543617b96068df10ae6ac493f45de8" },
                { "es-AR", "0703fa9bdd84648f714f7881505a9d82a777337778a37c4da65d8fa343dc9a058921ec0d976687f6ee9080cce78e2a7f261a98a2f0665d3f7fe912a4241a5580" },
                { "es-CL", "9217f9e8269f8473d620fd9fa23f0ebd8bc034585e56eae5ca4cfc714869ab52073695ad1c1a4b307864282b4bf851dd569f7c765ab443c03520ad825b4e7da8" },
                { "es-ES", "4de8c6e1cfe36ec4ff1b6fd2b84f2a1e0cdd2c4405da1c15280ab9d9531ba8124b6ef473747b2b84374bf136cc41e012d5779e09377e240f9e8c16ba4669769f" },
                { "es-MX", "b0ffad8da1329eb99ad9a049b15d679fa813b0810bdd0083e49e7704311f67bc076d5c0917621a79db9d08558d05ee4dbbbfc1f5171996d8898f65d1d41f0f78" },
                { "et", "733fbfba952b6dc86b717d1424969a529c31140574546c2d5d0d173ec08750d6ff2a59c286faa747afc1ad0c7b8f49034e7cd61811fdfa2012049d49280e825f" },
                { "eu", "d7296e75a58b0352f11e4618a6aee076d832e1304b3dd1caf519eed4ae387a52488f34cbf8853246c6b0e8a8e20c64fd62f745e14db7c5ea0d6bca0635500fdb" },
                { "fa", "59fcea4eb9ea8a47c1d9686ced6c618c42ab91d104311a27ce665adfd29be342cf9478ea917a7ba0f8d90a58a6c898c46a021d6887a7e1dfffe09ffed768e0ce" },
                { "ff", "52b69c273e49390c9cc15bd33d2fa5d9264f892793f746b1d8dc4c3256cd41197a161ba50294c1e2e0d7fd9c6b7dbee5dadbb49460122b2149d09eab4808815c" },
                { "fi", "9f0a9744bad23854c700673909382455942f182f53dcc9abebc499328f99ca4de8abf6517abeff88730d3f0691b3f597ebab2bc2f3694c8f0b9e7bb838db2eb7" },
                { "fr", "812ff0d7c5174cca4d2e0d77b7293bbb0bdd46a9d48b706fbe6dab6ee0af01060b9e094a4bc5a31a2b611fb3824658122f2831c2646ee84cf38df7b43c9961e4" },
                { "fur", "6030ea5c665da6c3dbe3541c4f127ff42b4c55bd3187950fdacbf25aba212dc35d2eed1dfc8fda50b6dcf912b8ca889f90b21bdbfa6a8f9ffdd2ae8f749594dc" },
                { "fy-NL", "a96b3e1605ac8bd6c93065e080bb527b07ef3362f69e879f8de09c6dbc14492af3f33d0e6607579d382d676cc47ca5cc08609a09a0f4f4469c5ee4fdff370a1e" },
                { "ga-IE", "629c55945fcf3a02f3eaa8eef7cc8c5b40b661f57006ae09e8685063ccac7ecc1a97b6194de50346e947ee417efeba6f76d15bad39f772f2b4ee0368f28edc33" },
                { "gd", "dfddd7758d2427c982dd76c6153aaf86da5fb041460ced7a97e1d70df3a822083f16d9bda208d50aadac60f2beb3334c30955105c0722fda83ff7149262eb37b" },
                { "gl", "00eee69343290f1f2963a02f696bc70c9fb080b09a4b9b4cea06aed674c5cd1a32a4f6732f25438ab111eb80c3bb9b3deefbe0ec7585f3e7b6e95a21ffc7e0b9" },
                { "gn", "63f1c7d43a1abeec9529bb8048c328af4cd96bea5a08dd94065efe362e95a7ebb53b90c5f6ead91cfde27ce4012a025575788b1efe7aa4203bd9dc0344dfb7e7" },
                { "gu-IN", "e904ad35e438413ee1981c0a0498308fc380dbb6e444578002f75db891fe03862281687a019ba699a69c79266e33b2ec697d848d8f0162daf8286188eea10bfc" },
                { "he", "035f295a8f43e622b6f3194a7f357616e2abb8aed474c75f8e3840e44cb56986ff2be6a01269f572737a638b35d256e49aab616290d2a79e5e7e7f8bae7b3c03" },
                { "hi-IN", "9a779701a27b8c4380d7740f53b65e1fc40dca0cfe562e0406a31839324500516d49536d1e1cfc6d36b02eb032b2f8082022935a4126f3ed1456ad891d7ad0cd" },
                { "hr", "2c4a8b7c85858703147a31911e4b7db9fb95a16a216c845ae28c8da4068ddcbb13f33d773f24d4f4148c40b5d378163edae89092106510e7aa5c2c77e2e97fb7" },
                { "hsb", "4dae7c9cd3840f615432061fa1cab73ac643b7db1622538181635377a45f9979410055c9e32b66de7f0ba548214980c50fc89654117d11b17d7e8a2a167b5be6" },
                { "hu", "33dceaed7024e239e441fa3a46bffe3c165841ca9ab87c0973f5ec33be3154f9d735394c6c1157a5c27ededfd5232272525031268a8a886f9c08356b4ac6cdd5" },
                { "hy-AM", "8b577d55c601723a2fcef732a4bf5431459953bfc5f6950390ce283a9c06d412103990e76bae3b0c696e0ba1c171b71f8d9efb3bdb0016fb93320f7d17df2341" },
                { "ia", "9bf689b416945c88f5e8ce03c843a5f8efbc8d68df75897de2e32fb0467eb913e869fdd74a2ce12fcb7cd7c369dfdc62a1f1d28ba50dfafb4660b3aa4a4123c4" },
                { "id", "e65317a7963627e057479f881c6aa8e96f7a32f78d0b5c5e95ac9f4cf505fa9c35f66668ef651740f162b9bd1465c1f88bcbbaa4ea6829d27b3a84b674f57e6f" },
                { "is", "93a2172c174338fe61a4204a6ca7f60bd2264be0e4f37efcaf09c06edf31c0ab65822cd508b7aa4be80999ee3b21e392a2958feb831765202b8e9306c352df02" },
                { "it", "3d06bd9142ecd0985700321dc43dcb167a60572a537c4730314424ba604a2bc00375f95bf558a592889bce2e273bc86c92d138a307f69a546b91dff6605e302e" },
                { "ja", "2e31195f75f8dffdcc7a30db7c0aa22e61c7d1940a3fced64a671a8ba311b2b0533b9a8a90744367434e9149ee31059a8d142bdc3fcdf8dc7e43bc0706cbe1b7" },
                { "ka", "4ef666152930f92851cafc6ca4ddc7f423158d508babbae959a1ab83f1f93452a6877428cf7160e49d711af3189d28b5b14a17511da23e4a92348abfa1680c5e" },
                { "kab", "5800572594a1bd21ba5557ac5031575018a290671eba4d7e62983405a60211db3617852e5f7eb126c22359c961592c739699d2cf75dfe595df486f485d3dfb3b" },
                { "kk", "68e8e626713a16ca60d0b6adeba60fe228ce41791a0443c596de0077d0729d9c3f89a9051277fa112e7add8a3141290ca9c9b8d47eaa7b4e442c993f88d9dab1" },
                { "km", "32b77cc8fead2e1e27c5b2eb8a8778a2af9786f70dea34b3618d47530364f6fecc5b141b96fd8e3e74f56522a270488a8c93fc70fddd470708685b6c51468102" },
                { "kn", "ebfe064142df39f4fde2cfc54e7d020efe4a0aac9e69e2f38cedd36683414b08254403ccb84d19cc6245d7585fca99c977fb51466e6ad363f9a1d41a3883e227" },
                { "ko", "803058a0cafd3ff0dcdd3a37fa6311ad723722e3389fa16cd3ea9b7cf49f91cbf3c4b8566b12e5650e849af649bea8a0f4b7763d6f3e5a4bde0fba21006d68c7" },
                { "lij", "04e8231cfc6577ece031db247660ff4dfe88dd9303420fcc6d555a2ac4c95db88aa7212ac88e8ee33916a7c6bf69d129bd6cacccf737c0f293850f5b962ba796" },
                { "lt", "7fe1ef86bb75ea00d77cc412f261963911dd12d1433ab038740ac281b49d71aca595196142e4e7fd8b8c1c91e308520bafb16dbfa97b4feb70570bf7d771abec" },
                { "lv", "35bd8ee89c6be005b7ed619780afd3585d23919caf1333dd49ab96d90bb02ad8dc3ad6d1ee590fb8ea3fffd3855efa9ad27594331bdd3505d2df26aba168e3f4" },
                { "mk", "cdb3faaad27f8e95ec877f6c250f481cc8a62a9d3bedba4d0903e0d4c52efd3509ed93827e9c773cdb156ef34639ce0afb0e7e167dc76bcf6c6d6bb581454b96" },
                { "mr", "7911636626624e72a07b3312704225be31083febcb7de239e392bb49632f4ae048eca3f1957ca53bb54fcc21d060692bd95c4c3934ff9936b54b2f3130eacc16" },
                { "ms", "e4f5d114c2b79cf2b48c5ce481399aac89ebaf7e401f2891b1ae13fb421001947e59cc072ccea2fca9579e258fffbff3a96fcaba253d352c0d5b2119743dde6d" },
                { "my", "1fd3413417890331c2113771dff21b519af6d3ed2c7e9446b9f2e0e1191775a3af0d12ec4f3c4bb0a964b817a1fb32061bc93b44505b1391b7fdca670eea8dc2" },
                { "nb-NO", "f3025a4f5e77074811f400ac3cd381eafb21d13241bf9c79201bb894c7da6356e47690e556c58b64282a7f93f48aa8b61b3b272ad355cabb46b16a840723ee70" },
                { "ne-NP", "a13faa71fa91073540358c7775b807d1c49b634978583db48c199556d841090c68d467a87fd1fa6a3c748c1fb73fc4b416acc81ddf3433df185ef92748361ee9" },
                { "nl", "755ef45183f8320ddde1e30a0025c00ea76d65a346e530e86c9d28107640e1bd75d2bfff4b854811bbbdb289f43e8c2d29540d7b08e6f5b3a78fbf2474b29fd2" },
                { "nn-NO", "d8af2188c018c23d21bbe8c8416dca1db78c4fe52295e2788766ac0190c854fa9617a0260a655161e034c9b2aeb8af239021e7a5b1e7e04bd694e04ceb62081f" },
                { "oc", "408cab95ae0afc043e7bf4503908a45f568bdd1c992baff5c2812093c7ec95ba19e2a830b5ff6546feb0d2ac5a82083f709a503a1f34824c9c700dfed7756396" },
                { "pa-IN", "992d1a48f3777c3619a2ef4874c0309a1031b94ff954643aabaacab1b4d9ed4c074b34f85a30c1e6feee0cc2bfcb1a825db8a3f92281feeaa036156aac69254c" },
                { "pl", "7a38b3aa879d8c28695e2401d1c292790aa9abbc2a8734a70925defa715d31288da9a6a5b3bd9ba5d466c73ec7965e550595fb02d8068d883279a900e18e53e5" },
                { "pt-BR", "2375a6ffaece418fbe112158eef3be102f5c603939692756a64c26549709c52d30e4fa4fcb83aa5f91842dd41b37363f65d2ef35f27b4666155c9de68f22427b" },
                { "pt-PT", "1f924ad8d5f937af2499e8b85991808ee2ee9ffb01cde26d5aadecaa2625528b322343a55da506456a3f17d9a5b634d323a0dbf01b876a404d70d5617a22193b" },
                { "rm", "4c8c5d6e1ba5a3f7a338d940b7a8c697d929b65e29483db89f744d78aa170ab8e368a862c527d256139ce62244e71145559048fba4c9ad17a3731b535fa1a50b" },
                { "ro", "f9b0e8563bebd6ee792244fe4869d4191bd267ba4b4383e0531736880008f470e6a2aab5ab25fd65c40d1c6e0b8f5f755748a995fece52815143740a127d4836" },
                { "ru", "cff76ec55808c49211c85f280d811b14a4529db11cd46867afb32472a5c8d26168e2f419a34c8515f2ccbf8b1d2c4372e84e3e21eb9b44364e77037095d02998" },
                { "sat", "ae6a9308cc2df3c934f8c224c387fa5c71ff97a6aeaa610b3279a9beb5278efee3398c800c6defcd73262e7c3919d66fdbc5d6f129f495f9676e94a07fe3f491" },
                { "sc", "86203ce31c53b40872b5e9cbf60c0489582160d90a4fc118c5fff79428d5d34f3fa4941084f1ca7545490b1359c039c1df7a827312deebd568c6ef8bc3f08cab" },
                { "sco", "072fa49b0f128a53a3724af0a1e90a1154b5038d0e959a15473ff4ea46ae51f66996e1a0b2620793c79b99c2eb948cedc1af31a1435a72f9b206c0772312efa3" },
                { "si", "d97f6c5be78723c2ac9178e468416f128679bdbbdf4b742b59ae9545494fd6d3888a9a8db12d49268cdcd84ddea2dd34bdb477827fd85ccee2918c99c4eb8c54" },
                { "sk", "844f8229e746f40a135393c2450c3e62d23ec490375b890c2bd6b06b17d58fd56ea020678b8b44c26f340423a1f50b8951d9b78f58fa90483f8e225703948dbe" },
                { "skr", "41ce93c77e6d6bf22693ba0f599eb829aa4ff7579195c555df8bd8c9385499051cee6d5b8cb63ced545ba65bcbc769935c67f86a710b4561d44eed5fbc2edc54" },
                { "sl", "1ded11c48c33e4a733b97bf3e6dc514913b47883573b5300e5e546a59a29421ad2d09c3ff38967055f163f4b6267445285c067458d494961271b17942e001c74" },
                { "son", "d8cab1dfbc9f2b9be8ac2756770efe8ac6ba985ce0065a34b1410979bfaf0fe6315eb642fa9d2266dcde090704c2bd7c8fcc66e4b6356fe27a6fa4ff3546c7ec" },
                { "sq", "6b78f7b12ce7524fc5f304d8688820e6177326b9ea0b1ebb18d8d2800153e3663d431239eb872126ae62f9e86f8279475e89c163403029c96ec87ea9bc9fa911" },
                { "sr", "0e144b20f7135809cbe5ab0c97250e9fdf43cea19bd6f7fa852602b20eadd7707473e398e1b0a30385bc339f23b55e5deed6d3548bafe0bf247195108e4a9714" },
                { "sv-SE", "8295aa6c603498f8fa6aa60c03646d71134033b1b0e607000993b81fbd024f99b43a20b046c13a6c4ac814453a75c6c4036aae4e399c1120fbbe938849b3dcf1" },
                { "szl", "bdc08d58e1307024fdf347139af595cf107f0c7dd8f7673db77409acd761791b22c88ee1cac88c09b1508943595fab4b9cdaeea93d2fd195df3e8017e5ce025d" },
                { "ta", "bf44c32822fcb7242b8035560aff4146876e853e6c7b217689c68cd4a70d1baf6dc516181aedb10a54c499fbe80432c7d39b68f5ce71caf2c2066004d3a61ea6" },
                { "te", "5a98fdfc7b93abacd6ca336a44c58a9e61e833a2d8d10f860640d0ebcf5b90dda176d1a0bb066a7bfd5441d24e6d3a0af861001c0b5d4dfd9b22846f666c5a6d" },
                { "tg", "751f89005863891fb02749a110ee4fb10680cd025f5d79934d180de2907f9b7dea1f2c0afcd40b839a9d930ac7f39169f3354bdae11fc1d245285a9225da3677" },
                { "th", "88667f285f01b8d37cb0c01aa88ba243c4c6b80c01f9ed6c4c9533ac9dbf126dc8f91ec6a2355108517a2d82dfbef90e309631524e5f5a680c65c4b04ba5a65f" },
                { "tl", "b21902f52cb7994236e4bc877551a223432cbee6a3c59a7bfcc7a0be15ac04647188a56ff76012b9c16203492c1b5a2574275933291e175dd236f51eff68b70d" },
                { "tr", "616bb801c8a4d4a62917fb3af53d1d3495ee44609043a2a88c1b2cba07b2431c04b62928bbcd8477445c7f02fda3291d76b37be6a6c0fbcfcbe2d0869962ec09" },
                { "trs", "0427f1ffa65a935a539a75841f66bd931ac7f9a6bba33654e06a4646763990bf1cfe3c485e63e2e8f1f4ac5663b5ed272d3ba36c4cf5098e3a816fbe8ad3099a" },
                { "uk", "f5ad7f317354fc52581526ee090bf0b7765bd09f47d5ec4a43315edd46e6069ee0dd205269f099dc0fda41b48031578b9e82b30d0fe087f857e75989ad456613" },
                { "ur", "7b916278d0853e7dcb938fbe387ea9a343a45b9cbefe9e5be04775db48acf136370d9177df0f1d3a89f4e017b6b809d6e0ddd48215dee8cc9b0df415a71b112b" },
                { "uz", "9ffad595cd3ef398e885ac753724f8276facd3f047b23bc59d2dc25efe6a12019819992882a63993e48cbe5ddb6d05ee1ba37bb2e67b78adec6ecd9485a1857c" },
                { "vi", "fc794664d613a724100bbb1a908c323fa79e367bd7202efb4ca218976850607f2f540387ab0a7cfe618cdd1e60c9cafbbac9ae489b0f1d3840b4643c6340b177" },
                { "xh", "529fecb608af420265e0d3036081c06f178c56cab01dc90e7133d9b4548cb738ea444a3720a348dac41861459588d103f7d5c99a03f6169248feebc96494f603" },
                { "zh-CN", "57447b75e4b41962714df9ab3f58e2f326bf5ba8ac0288607ea204ee4db5f5d1c9dbedad377e10ed265c240ac7f8e6ea7162a928ac867191dc50b2a6d2cad7e9" },
                { "zh-TW", "4faacf90af5e993b84563992c9942a9d3c73a4c6e0507864fcfb432122e132d0d419a067b8a9d2b53f9a5e6b7b10d91af3a10e3d7db5918e5cbeebf74687cbfe" }
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
            const string knownVersion = "160.0";
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
