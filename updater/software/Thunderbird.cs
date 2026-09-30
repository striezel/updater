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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;
using updater.versions;

namespace updater.software
{
    /// <summary>
    /// Manages updates for Thunderbird.
    /// </summary>
    public class Thunderbird : AbstractSoftware
    {
        /// <summary>
        /// NLog.Logger for Thunderbird class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Thunderbird).FullName);


        /// <summary>
        /// publisher of the signed binaries
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// currently known newest version
        /// </summary>
        private const string knownVersion = "140.17.0";


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Thunderbird(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.17.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "c9f6a37dd0e5e2d372de09abdc5299385de8ee86a88f8a0da9bed937af328e8901808dc258b7a88a9fa23a4208b002b076d80e2cd953f57a788b7f9daacc0cf8" },
                { "ar", "f79a332f60868408f66a7347475450c381e0fa7963dc2e7e5f1b346956af63b48b53ebb5d8b3bf310042f609bb5124840d36957c4df067a2540f4999c215a87c" },
                { "ast", "d7766ceeebc88f1acc1bafe9f27a6818fabea9071300b87bf91d1464882ddfe969ddd58e59f6eb9109693a3501f22877f8f6365e75ce2bf352c059260df4a6fb" },
                { "be", "85292c1b7c4c1e26d616369bdf0d31cd4bf8d161f7f138da4b7b634c6ad740e12df4dc0ff3fc9d8f12e4de293ecc63126a64d9c1eab35e2bb4575b1c65fec5c0" },
                { "bg", "0c6b32a6851a8babdd29a45e270abfdd0a2e5c4a3951b41174bff33a7a336b583932221ea6cc3ec82382321cc6c33cba1e86c80ff0fcec93b0b1f645d0d117d6" },
                { "br", "81a4e0486853bc75c15bf35422962b86f78b7ce4b8bd3b579081a2e6ccfbae50e068d2a1929e63517968d89071c80b04165581aec04b1217710a9c14bf2b7dcb" },
                { "ca", "a0c72aba768998ba7476c605c98328edd1b45fcfa4b6ee744c47bc56c636d118992b08b79b9b370cce4f0af6a5382a2af363c1e53d70b4df14a18cc844ea31f8" },
                { "cak", "7f5c2ef67de1bda0e59306219c7652cb61c8aff1ff5d7d415b7a517c6a232511f38b2ddcd82126082cbb0a2f7e85f031e4340a67e33a9a1e55639f2324f76d0b" },
                { "cs", "ed1a0da3338b1dde6aeb0b2398300a3c9a2c2b811ad020a838560d712763a658a8176c6ec2d2a067047e9c521c47c89362097388c78e80aa46941583aaed58f1" },
                { "cy", "07098729a801e8a591438f6d209b5b9b37b4d1e6cfa4e9ba86445b6f67e3fa7251c0792730430e8cf9ad50dd2772badc5f48986745737014f52bac2d19ca5211" },
                { "da", "4b3623986b9e986226125a66b17e32d9a14d5ebd3251497fea07b67dc0e436ba688aa71cdaf9535e368a1092669ab71782be264379bfad9c19681cfd932eb188" },
                { "de", "c1ff5a8c58de70c9b0f032266477aa7497a257c50efded43ade7b483c564778a75d4adc1d47a187ccde6c972b86b8ef0aafa1192eff495079daa2fc231b24a75" },
                { "dsb", "59c2d8ace70f6eadaf26c54c1c14d57180f378b322dddfce67d7c4d08012dd6e28a71e54deb2d7ccd5bec96cd0e62327011044740d68f7438981e62294c85fec" },
                { "el", "2bfe45bb4eab0c9a84532be563be5937f5cc82a33dfdcb91224cd66d48a112fe33af183a570a040f11930beaa94520db70641329eebb7cc1161a4a00c503891a" },
                { "en-CA", "7df8e0c794db7207f901ece7887ce82a7c1e95f60896f4628edffd225f2a143d2e0d4e474bfca77c72fe50c903483d69962a485322a076b1d02053a56fafad4f" },
                { "en-GB", "541059903db3e7fff414a0ebadda4841eb15ad370dec4baa043a308aa1586384b9ee8075d1bb27f7c9b71d0b0f044d13f461d7c33dfe2d905cce4e10b9a76d0e" },
                { "en-US", "7f08142faa118d7da959be402b02f27072b498ffb873c2dea0e13c50d8aebbfc1ccc21c54d4f64739b6a76b9cc0e0c705633b2e8dee640c0d69719cc51914600" },
                { "es-AR", "29b483ce8b97543e5122893986235439bd4df2f64cfe36c1623ac04f0275b102a8ff68638658d15ee24ac9de09467ea4991f6175d5976680e80701c7d0efe584" },
                { "es-ES", "3581afa966028a66b7d9c1052a952095f2194c2462c441bb909b6990eee22e0049f103886a98f12b2543817dd0916264f71f15c8e188f8a4e7b896f157f6031d" },
                { "es-MX", "d4593ecb824eb16f7909cc520b0a9ed88b755258110c6998209b6a978c80b374dfc83c7acebba910f4e4707f31d2fab7ad2d1eff3eda8c43e3b62e6cfbdede93" },
                { "et", "90bd7e8d82aff9d08612940e6bf4cbb07f2444eff100a8b9ed80a8b668502101d55711ab4a09216cffb7891d21357faa26d1523aab2bb1c9380f8e31afb63cb3" },
                { "eu", "9451f42b4b97ddadca672bc5a3f02ac268528bda12d8b861a802dd2e3c63a78d0e7de517dd9964f9e4eb654f5ab614edf602b4b8f6733afa393ce9070ce5d42b" },
                { "fi", "5e11dff597d5bd9b236e32dbf7bec84f9f48a26ef1189765b093986355c3ef453cac375bc5a3fbdfe85095bcd43238f72cd8a5b05bb95300ef17ea09ca231a6c" },
                { "fr", "ded9e20573d0018955639ec2c6f55006f68e5c59b8507545c88fd6c1c21bdbbd4c621b21857f889b0f7d920e6b06bb4b5c590f974bacbd5261b332088538f972" },
                { "fy-NL", "e66399d351e6198edabfcd4d4bff4b51b3f9a4ac27ea0a3043d4fd053d856e3c89cbf2d8495fe5125ae5689cdd9d2bb89841cb1a6d84b3bb5091a730acb0a62f" },
                { "ga-IE", "bec5ced4b8f67755794513c58ac182f7a843bbebce76276313515f85e22a2c002385bcb576f242c9478f7b7db0936fd50cad673db6bb9608568814812ee3d80f" },
                { "gd", "8ea88cf61b69907ae208b4fc73030ea2fb26c1b631998c268d4ed143e9064a26ed8ab8972199fc3430cc3ccf2129add90b36c4fc44369e2675c115e32dc9db95" },
                { "gl", "f807ab07938eea351a6498bec5ce5ea7e9d0ed3fd86cdba47669211fa68dc63f03651faf7d0ed06b275346bbbb478c728930156b51ac95dcac604674ed864391" },
                { "he", "72f636f498d1cd8953b789b27b6e3e5380d88573898aede36a009688368fde5e22493981d833f684de730c82a6e73a9a38672a7c2ef7ab3254317a23d28339d1" },
                { "hr", "0b11c703cd9ff38b2adaadb504a275b4317b1e310e77dd6957192778fd16ae64523f429bc9a110bbfa4dac62307ebda71a9cb9b3c6028896ca57a204d9b682ed" },
                { "hsb", "2353b5dd730339b5c17114e31ad220a40158cdc9065f0a40aca55d2db8002ea1b5839fd8ac85128a0086f64032b411a0594d6cb2abb68adfdfd2733d643b1bef" },
                { "hu", "cb8aea08f876e9b6a6b3a54d469ffc667039de45713f44337f45df6c7147a11b6bdc6ae903228aec06942f503861e6aff2a08f63c166786964f0c7a253b750b4" },
                { "hy-AM", "ea77ba3ef1005d362dd674ff930d68b7884ef1b43b6c4ee8af1ae6aed28d5ce8d281234457dba9b567e234ee89085a1781fc0e11b7a85f9a20d529c1dc2a6514" },
                { "id", "2d6bc1e4ef8ca028e743f2975605c0eb7ea0684653b3c3d246177ddead594911c9bc9df27e2907c14e4cad60e6fa9d78ba693060487ad823821ad6cc66d707be" },
                { "is", "b33fe25f98ef127379501a5625e32ee495a81d19cb09eb1d5dc4662345ff9553db8bf5d2fabfbef2b572ec8f4fb872a9821ad33ea95bf3632b58ca33d2056957" },
                { "it", "67ccfe9c27bd7131d081b73ea09c0e87fe2c9ee26370b045c05df19df55dedddc10a21bf5f1b4ce555d735a70186e02cba7af127b7908204b58aa9ae34cd96bf" },
                { "ja", "295579b25db5b8d3edf94e2376bc214ee0d1458e8ee0b5f01f298948cf74c81938ad515343c9515ddd724b87defe12b444f192f179989a7a4ede214ecd4b2408" },
                { "ka", "e83c2b289259dad4dc48ba7d9222d330db95bfcd097407f5aac66292696af90bc355876b01a6dffa347293612a5cbfca06121c34c6c1b8b05e7e85bcb1c0ea08" },
                { "kab", "2c2eb63dec3cc52147a3318208cc0395a1cca70c2dc3a93e11e8880aa3d9f885791619d138780aa2f0f1f5f14410728f3a7dab47164c738bb18920a88f0b44ce" },
                { "kk", "40086f1b6ade481ef766c0d84481526c1acd01374bdab7eb738f230772f41277b41b631e3ac5f1903be4c796a574e407c223e87c5d45afcadce0077794622b22" },
                { "ko", "e25ab611089e1c8a4284310838b28d0492b03952f2cc0577a6ab9d9b5994cfaddba6cbb0f2e7d4b53aeaf3bfac08c376010443afb59fa1507fbb9946580062f1" },
                { "lt", "f2fd49b3d6533f7d1ee745d9933cc53c0f0d41b1a842c115ac7b39090a513b330fb3719cfdb3806d851f982f65c629159dff2ed307e2d166bf8d2fa22a33af9c" },
                { "lv", "91dd4b6108f1813d1b334ca09c903c455d11c3a7c035c93cffe8270f8c7367875e2d73615e37f2c86a9d41efdc97c7cb1197b4220f1fcf9b77651704af07e9f5" },
                { "ms", "c737cbc00bfd620b5637ce957d8a112c0c86e52f611b7f40567dbe8509175682b7f956fd1dd315c589947d4b41c29ae29e4e6a6636ffdbff2b02038c61e1d40b" },
                { "nb-NO", "b28238e02226e326f9b21e3182abc82aa662bfde1403344020a056606b328dd95d18ac9dab3d1d6e582aa6eb854bb6a6718d79e855435bb9e40914e0068bfc7b" },
                { "nl", "9acdd96d7d226205c0b1937470c92f1247e6e64de840cb7be11fedd38bf27a8e465e69477b9b0d5dc4341314649ba4d3f3cb00c354fb9bbc63c6a46572dd36cd" },
                { "nn-NO", "fa57c50cc0b3118fe35f5a2de7dfc6787eba64235158ea387b0d1f4f4a945dab6516c498d9e1ab7dcfa07862ca0aa3443fdd263829c34c3774aebc2569ab43f2" },
                { "pa-IN", "62fc7e2887654d03c625e89ff7161ed747e986cac53ec4ed06fe1ef626184fe877b67976f0410fd1b6dfe39cfa4a038d8c81268ce6b59085effc8e973238d720" },
                { "pl", "24eaee649d509dbaac7634f599627a0026144d04a29423fdfc43b5d0a8fe1dfe52524fdffe671673ddf3d5673dddb98e8b0d89e30c4023944ea9e0d0b5bb2628" },
                { "pt-BR", "ce8cd3b2e3a76680e6601b3606eb3444466c9a58a42a13103015874e1254575d1534a2e85bd02a0a96f58efafd667ef924bf6d1b4e9a54ad79d342078cb54dd9" },
                { "pt-PT", "45a378b6e7cccc1e36eb1c881b56d179a47b82eff6b5a888c6edfb3c901056d5f67df47bee368f8a993e94646fd0abb13d3fdda6a50d5ad4fc597eb25111df9f" },
                { "rm", "ef0e74b8e25ae36de55d4f299fd25b8b74804e042a808a47910ccaafd2097f15d8bb13183d4611391d937b0073df6cdfeba0a9a80a28f5320ef52d2c2a8cb481" },
                { "ro", "84097d4c9f052021faa59c6b45e3cae262c937ed1e0d38e14a38b82088648d653540ae89e3e18e2d27a12d869da2c728ce55439eeada4f25005cb4e963496d72" },
                { "ru", "2780a1baac7848dfe01fbf0ebf33b1e4a7de7f9b9a610285e5324f3b99e53ad3e973517bd2e81edd7c0db813f2f042f40bfbf48dbe46eaa5278fc07bc9f44df8" },
                { "sk", "1f53272179b12a06d41341ad4f51fb316c440485961afa770f98d434b3158565a9d1527b6526ceed737bc2565c406659610e26847bf84433154d057dea83cdaf" },
                { "sl", "2dfcfe41c56e1571111531f0ef2a7f55906e71da1f5c1ac80d5a14acb9f442faec57def05550efcea6420202d108e1ea6ba44dac12cb6d3bf9ce651649f4ad76" },
                { "sq", "18acbef2e89dea3209d99238a0e7bc8a2c29261fcad4501ce7cb8a4a738c269eff5346789d44c56a36d5838a488b84f1e7150c022165f47357ca5e0da32bfa90" },
                { "sr", "4bfd9f057eff022e6cb969d9d99223997f46a22c34346128a16bb08ad2f048023de4e0f7ed1e5b6c88e15105ba69dd3d77f79b440b849ae96da04eb278dc0cbc" },
                { "sv-SE", "d7dbfc9fcfabcbd6a63d0c12b8fe74f88a1624dcd87466c098c283402e786b79c7c9510cd2c0632ce1e40e777a62c0eadac74f232a1e557fa7b5c1a856e75dc4" },
                { "th", "7991e82cf537fa5b647ad51787e5ba8f49aea08a327aa76d13bcf2d8407201b07a60713032f8f9daa3b7d009c4f432d99cbeca1ccd830e3bd728deffa347d973" },
                { "tr", "9518c2840d7eca1865899a3b19f62445e16c15e1aef350b7b1c8bdf80f8352e161996249b4bddf6d2c89b1a5ff7dddb3733fb393623e0a290ada69944e2299b9" },
                { "uk", "3647c973bdae816a0b26bcd13515b9930ccc64269289be4a66ad70d52a7b557fcb4496b9e007f139f20ff0781645eb7ef06165b423dc1243d3c85e34438a233c" },
                { "uz", "fc7c87ae34ee7e1f57b25b4013e0fb9ba2b22250ce0b0d20b4098e992d0e2de9762a254c151f0ab417ec21d2df254cbb3650f0048789072c1d0b5721f22e5699" },
                { "vi", "c33c74b06a5eb828cd61f1eafc4bcf82ca2da563802693c6ef5814de1f59ad7b00b921a1cd9175cf6d39288dbf9841a0cd97bcd037d91f67275664ea30423663" },
                { "zh-CN", "98fe6823a601e74a49d222665f1f48db6919feee298fd2c1bf2e52d74fe9e89cc56885446e87fb6b52417c9760858cf67cdf38d858b7f75905922ba990d8998b" },
                { "zh-TW", "948c03542d5f4d5a5233e4094ebaf71f307894fd2cf34b79cc2ddfa154a13f9ed1a9bb565769c7efe7a5eaf9a9b26e514699be9406b655e0170479b13372a5e4" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.17.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "396e5d95381e5ff36e3673f8c815c19385d9024bbf7fcf6d832b242441c5e1cab041377dae72bfe7f6c60ed717b3e49353cd8f3219694b174468f6b1aa3ccfaa" },
                { "ar", "e0a3af2758434d45bca36c915a39b9a131e83e2a6752de1563e598ce7bf74ab4efc769b6e685911ce63646ac7f4e8c9dfa593cdadc0e60d2e102068958561107" },
                { "ast", "5fab21076ac084f79a7b0cdc76a5a648a92e55cd0be674694f7056ff3efac63ad2516a34fd3bb3f7d34d620a9accb76bfa37e7d66726e3351ccf1b9a7f983ff6" },
                { "be", "4f985c294b317829da58800107c25350907ad321416020f15df239f50364614bcd224488c2de495eff8f6763b1100a3928cdfee9d302f4cda8d1f8e33dde8cf0" },
                { "bg", "419764b28a257e2bcea57749a8b7b94ec58b1571bbefd723e069d0eb2ee63f7cde1d9a66291cc0ec2c6112f6be5d53e74317218de64cb02435d0a25367cb5b10" },
                { "br", "747d4b35955ad80e356edf5fa446127bffcd0d6cd012f61d8225dc398ff3d7665558c2b2ff097fc0d72b0c76ef62a1394f50f990adba8e20e1da2a3c3f51ccde" },
                { "ca", "65de72eb37bceda98904b613eb4c61766810c04e255d6e9b715c3e19fc866482027206d25c67f7b4d8a1f13975ca437f030685ccd98d7a3a2a8083071a80e753" },
                { "cak", "3156c3cca51af111453da83dbcc30efb911a3c495a4c00c8099f26b2ff29c2e28de83d62af59ca562d8d84ad5b6a0529503e2f7223d7be262ae813d96128ac37" },
                { "cs", "3e33ab42037db579204414fa4bdc0fa237024f4d27ce5e5a2c8e5a78af58f737926afe017ddc6c3b8294699307eb828ce4ece81efbc0de66c6949fba8899cabf" },
                { "cy", "211ed095f13056760cff9497763799876d20726a8434aeccfcbad0e16e6b3075f180dd206c6cd1b0bd74150d8bc8f5e91059130a0e03e920485a8e0d04992ee5" },
                { "da", "5d643d8264cf052921df4d67b555daa00a7d6b17a1c6d21005f31ce6ec1ad72a1b1c4c2b3b8c57cd90b05102b4fdce1f2ca8f6f6692e01b29aabd33b7b9bfc13" },
                { "de", "6561eff03c3d2e074cbe1d19499e9791f6fcf2a7386f4c0b3f1dc325e30ec4dc86e4075610e020f3a5ad366705c6e9000506ea96a98d31b4ccac87be9ba90573" },
                { "dsb", "5dfd241baf694fdd30927b3c6b2ea49aa70b93992d8a784dedd1144461423ff25bc63b3eff066c562d23ae767aba6fd3176fc2c469b80ed85a112469f79fe72b" },
                { "el", "a03a229c591097a46f36bc4097527e9eb02856182fb9c5997680ff8cc79e91e6950efe052928bc862d0930a9f359097d283fe30921f72fe5d4e7ff63e05b348a" },
                { "en-CA", "32a183a5048aec642c1669b338a80020201aeda8474bd5d607c6d2549663b4cdb0e1b141c19f3921dd1a070a966df92b92e7ab84f6f4c80261a7fa6e565b6d2d" },
                { "en-GB", "c54c41d0d422cb67a4935eb96fa4f299ae77f674ea8fae42b809d2fd66806359996825573f90f2fe7ab7ba58ab141114038434bdf66f51e136861e9ee12f3399" },
                { "en-US", "41734487d8e73ccf1d1273d2f9c8f7c510b5d8b9eee4b01e62903439d1d83a80a6adacd518958cc78be3e0d5a4cacdad5d15c9eed644449a62ed0559e18d7c6f" },
                { "es-AR", "eabc13151c0506fd9338c4ed079a956efbc736c39600551bc5580d47ddd3ec049413032db9e3d9f460740f8ad8da4ddd7874eb0dff1b2c0502fc8b0a906a392d" },
                { "es-ES", "ac20adf764440fffa451305b57660543dc9c705273aa40865f3f5b652ee74cb7b28068a78484d191aed8213c8c96ac4b6e15e463f6faf08a28e1e74a56ded2eb" },
                { "es-MX", "5efe7a31bab86504ecb45ca066fdd3fbe57e9eedda31adf91acf6a2bfce3aa199e28bd3bc10f009c230211ac47c95bf7b986579c42ede958e6468a1b98e9ff4c" },
                { "et", "ba412cef27dac4cd502b3d42b43ee302c5ce188a71f84efc74b5036c1f6f770814a65129b37c8b8ecb2d82f555376c25a4a1ec253648931c1e29050eb0365e41" },
                { "eu", "c32a51abc4021116e1d237e12a4e379efb3796750acfa869552c4f8aa2ac9885b1361a864e6f0885049e50c7261ad07ecd3e47c0c5a61ef74f709d7010b60a06" },
                { "fi", "58594461872c2749c7b78a29b6c671fe218d8fdefcfbaec68154d878f7be0c7f7abc8bfe74acfe497432ac437241e3e504ce7c05333a74f87fd88afa838c8465" },
                { "fr", "bd0f64e50720d5284ef68fdb7b1bcba37b4e38840f4394cf57de93b85d407ce725f45a1fce8ba3b04e7aa126f3c624379378323708a614cfde89af20736c3554" },
                { "fy-NL", "1aa09cd1eff424d6ca712ac5f23bd03e7fd3c35ff39ccf7976961a6396d0608f0e89facc498703a41de914363b59315419aee1a404072fc79aa3db6f9531f533" },
                { "ga-IE", "bd8e4e582132a5a6a7aac2d02e9c4712bc77c645e39dbfd8582949f51c49931f475dd9e2262736c1d60ab303ecabcdfc4be3807f5479f5bbe75dc31d715ee741" },
                { "gd", "6c18ccce1a96fac298fcec832963cae48cf6f391a763d436795a0d824365ddb33be513ee55b592a2a6f367c6e805e14721f906ae9336ae7e815780fb925cda8f" },
                { "gl", "90720a862d87284816b2f01427a9939efd38a20808d9a3fd98736687427d1671ae6616d9b65d4fb73bdab37f96f24a3f700cb470ea7d380a30dbdfcd0de3b261" },
                { "he", "cf25983166a63f3e034457c1247ee6dd149563dda9af2c8b2646ebb9f81e61da2384f7b4020238b9b170a7ead76cf0ef32b515c453166c1fc4ae053e41dcbf5e" },
                { "hr", "0d86b7314d6de16df7b4e4713dee742800625e87e021f25177b781050403725eb9f3c44cc60fd64fbdf6c52e5a5a619e64bd6ceb3ca06512d21ed9908dfc938c" },
                { "hsb", "003023343e85afb43579eb6deaa4db3c79625261eb2ab5363192b49affa465ab0dcc84a4f77cf29f8cc3f0a116976de12dea149f48c3d51477e33df485c02676" },
                { "hu", "c77f417fb77eed2489b918509f8c0e1055e861cd021edce06f7b5508a1455ff3e15c34d02042aedea186991211d85bc288f8f2393548a28424b2f64a0baa369e" },
                { "hy-AM", "0a1cf0b31583717b3f0d0eb96b88bfd1d2d50eaa4e786309d8e7212903c89b9648a33bb21bdf01ccff4018ca2d7f6f3b02b6c1364eeba7641ffb24adadc95d52" },
                { "id", "c43921fbeabb123b4291dfc75f9595ee8234937072dcaf17486e886522b2ed586a784eed7650d06fed18eea080d224fc2c6baa220d06ee507f80ff086c9e9c30" },
                { "is", "7a6c2a990ccd1440b7bbca7e9caf2df7f30fe7b5a22237b5d6b5edc5a824ccdb52535538665e4b1d5fe11ac33f38d5572f9e97d6560738c95c6e5984bfaee772" },
                { "it", "817dbf40105332e86fd0261c3f8202f3592ee7e9ffb6c12d2425a930063cdfd589f3b3f213f2efc47a5d0db867072db25bcb80abf87c22b84e7f11657e422603" },
                { "ja", "9dcb1f20ff330448508ed4470f82af7b21014bb33ab6ccd5af2fb144ab93851efe7eec9bab714e1e4b969547a9de15c0f113ef395fd9e1f043b117718559a029" },
                { "ka", "5852da2e9f79bad9fc6ab27a4cd3738e7134dd51592c341137c7412d9ee5bc1e6051df7a7a5d651ec332d68bc0cff170f20e042d3635a5fe4344f72be7802258" },
                { "kab", "f71438284af99d7fe4d626708debc42606f811213f2ad074c1943f2ba070f7c9a10a849064496baf019754ad7f3dee3b9d1a007b403aa4ba55b6e0e393daa92d" },
                { "kk", "37056be4b5db9f6adf6f7b332bdaf6ad3fc8cd7b6cd4d82285c24f6fad9028f0a05ee1e1335a88736f680289d07e8f7f83610ffde4a68899c967e29572b5b681" },
                { "ko", "7b203d0c95e2cf3fc07dfb47cf5bb844f555a2aab1ae4c9b38ebb3abb1328136db312ef4a07492240134e8ae57b4e93aeba62a83023f753d7c3b3564221cdda5" },
                { "lt", "4c7d33832580274abd7f49ebd049fc595beaa69dd772dfaaf69df3b9518a9a1e0e371b6cbbf4cf0f730efec03e0c290e8c6711c010774fd6c2bfbfdf678b1b95" },
                { "lv", "a7492d269a362509f884e5804eaa2363417ee777ae52cd3b0f34151efa7defb984b59b4290e84b9e8b0bf0bd5d492a226725be250111bd0c92f23e458b329b64" },
                { "ms", "abbe292e95f4b73504ead3475d92a0bfa6c5781a773f2c2ffdf934d7967afdbc3a8e94885e5ed0a6ec593ce0b13bb6dd9d5d57d1aa1f5f882b189107008257f5" },
                { "nb-NO", "75caa54aad47be063f1cdc1e38bf21127d26768f60f482d9acb2ce5e628e30e9ba4468a9adb72c3166b7dd829db2cd62d3b78dfc26a64a242635e0b3176ac77e" },
                { "nl", "4c76fc47e9a391af230f58c1b4de45be741ff15eb52cd26db51bfcac317c63fc4e42a5f515df3f6a134e03cb70a67030257d0d503d4d4199c77a8fdace6f023c" },
                { "nn-NO", "d28ac37377ea254b1bbb680c7a553edbbf65e71b90d7846b0ec654adbdefc9026c55523c22e7f5a72e4ec273c3cebe765cb0ca54772b36ae09fd22733b6c68e5" },
                { "pa-IN", "072737ac113145785ac4d355dc4184f4ac59f5f1d7687db98d6db9ecfb7af7d05c6bfe4b79e6262e1f3cf1ffbc30e90cac96b0412e15365a95a3980b590838a4" },
                { "pl", "a78150c90149588631691dc2ff216e7bca1e44fbdf9d28a1aa8d0c8f612fb2d3ce59e551fcb8877cf9b6ec2d9166b8fa14c83d284058071f370b9468eb02adc4" },
                { "pt-BR", "fd8f05fd405b0c425fc14a2a237ee976d3a63969b63297bc38d155edfd19ca007cac2937654560ba94143cbb15545527d5ef4039c8afca9df630119f63d751d5" },
                { "pt-PT", "531882f7ea33212a2a922aeff554d4f18cb3d94b76023210115754d2ccdae9de3b3e0f439a96a138bb617808f7fd56f94fcca5ba91b17f53da285a1bd5783775" },
                { "rm", "92fa8d139259f8df9de2d48fc9971c1885d691c9c48baddf6b3df88826e1c7ed4a5f47be5ed366c019d1d5ccc52da547caf8bab0af9ea0068d543015b422282a" },
                { "ro", "8a2523354e6e717e2c24323e5a5a8debd235feca392249dad20f4fbe37b6a2c14438d6080add3910c9a3ae96300edf48e66f11573d0eb531d10a58d1b7e4c7fd" },
                { "ru", "02a23461df8600ffbf2e7b0b60d7563c3ce8cfb19d39d5eb21a8fb1bb9df1685f4aece192433a9b60d1ae2146d50875d03c48b87478bbe4e444bf9b7e23b6ab0" },
                { "sk", "670853c92bed28b27eab07c0a2162aab76d684617f2c0252e0aa972f6a0e0146ba5e0c9f951de1eb0da8fa41aafb1d588f0819eb2a58c679761079d887cb6622" },
                { "sl", "0a53295b19b10f36849b866277e7c48b0983e885b4de7489a0b0abfb313b1947522b83f6320247780903b614d646b31344bc63f2a24dea92bc43fae29f6b233b" },
                { "sq", "d3041218d93f8135537a385fa4357594d0bd9bea8ab72aab382cd810a64b0c64f231a4cefbc9beeb5577684bc22f38db8ed87398a191aabb0e17f2854fa5440c" },
                { "sr", "c86eb5f6c5940b7877c7209f6d597afda3348e115516b9287c5e90ba2b16be66473df00ab06cff6e691465db10c9b034586183b9094353813c03dc5c5dee0200" },
                { "sv-SE", "19dd5635d9ec1f9ebfd41bf18d89ccf3708318fb7618212b4e8b2a8f09979845cbadb23bd655fcdea462fd19e918bad3e3cb2ab2c692d3f7e95487fde687afe2" },
                { "th", "5da89c644e1ea07f3d16cf1eb879e4e239b8048298bb5055b6522385fbbc37ceb4784dd64f72d69391c86f5b9669ccefa01fa48aae3ccde4760344e2436a9e5a" },
                { "tr", "52b7d32fe306e73c84b514e648f639f2c3afd1a0cb1341eae025f5249ecb4f40b440e249ee105e3335a40e825aec5a1fce02dec825fb01e019f5be459a627d59" },
                { "uk", "5eacec31b07a080e927a71e75c349624370e58f0237fb56e9684226f09b3549f477a2f27b74a2bdfcb70540319943ed693c40d778becbec47dc748f05b6d79b9" },
                { "uz", "3f2707790741e57a041009327335d065fa4bf9704f7012052f08e414ce78d086b181048898368d2ab79b6bfb5e2fc3618a454415c3f3c29b68d8cd53777c22a9" },
                { "vi", "411b13fa07f982e0d5603cba9bd68981e921e491ac8b90275ab0d4c6ad720b0e33dc748ad7660464f1a12813b109c9e427f6ea88059f3c5c1d9fc19aa53acd88" },
                { "zh-CN", "aee49a05de6f9129e0833c1ebd8ae7f96bd6386bc2c097ce75dec867c6436c3dcf83e8188b2c5beae03d78a5c72ff7d527a17a0129e0090a638d5b7dab4e751e" },
                { "zh-TW", "fbfa3324ffc1bd3f2ee279e80b7df0365fad01c9373a3dc1ef255e09594d03f05ae1b760fdfde26fa585dd07f7327e288fe2c65cbfd30bf92f05035f6e52d7c1" }
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
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                knownVersion,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?(ESR )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win32/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + knownVersion + "esr/win64/" + languageCode + "/Thunderbird%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum64Bit,
                    signature,
                    "-ms -ma"));
        }


        /// <summary>
        /// Gets a list of IDs to identify the software.
        /// </summary>
        /// <returns>Returns a non-empty array of IDs, where at least one entry is unique to the software.</returns>
        public override string[] id()
        {
            return ["thunderbird-" + languageCode.ToLower(), "thunderbird"];
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-esr-latest&os=win&lang=" + languageCode;
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
                response = null;
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                Triple current = new(currentVersion);
                Triple known = new(knownVersion);
                if (known > current)
                {
                    return knownVersion;
                }

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Thunderbird version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksum of the newer version.
        /// </summary>
        /// <returns>Returns a string containing the checksum, if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/thunderbird/releases/128.1.0esr/SHA512SUMS
             * Common lines look like
             * "3881bf28...e2ab  win32/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 32-bit installer, and like
             * "20fd118b...f4a2  win64/en-GB/Thunderbird Setup 128.1.0esr.exe"
             * for the 64-bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Thunderbird: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return [
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            ];
        }


        /// <summary>
        /// Indicates whether the method searchForNewer() is implemented.
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
            logger.Info("Searching for newer version of Thunderbird (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
                // fallback to known information
                return currentInfo;
            string[] newerChecksums = determineNewestChecksums(newerVersion);
            if (null == newerChecksums || newerChecksums.Length != 2
                || string.IsNullOrWhiteSpace(newerChecksums[0])
                || string.IsNullOrWhiteSpace(newerChecksums[1]))
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
            return ["thunderbird"];
        }


        /// <summary>
        /// Determines whether a separate process must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns true, if a separate process returned by
        /// preUpdateProcess() needs to run in preparation of the update.
        /// Returns false, if not. Calling preUpdateProcess() may throw an
        /// exception in the later case.</returns>
        public override bool needsPreUpdateProcess(DetectedSoftware detected)
        {
            return true;
        }


        /// <summary>
        /// Returns a process that must be run before the update.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a Process ready to start that should be run before
        /// the update. May return null or may throw, if needsPreUpdateProcess()
        /// returned false.</returns>
        public override List<Process> preUpdateProcess(DetectedSoftware detected)
        {
            if (string.IsNullOrWhiteSpace(detected.installPath))
                return null;
            var processes = new List<Process>();
            // Uninstall previous version to avoid having two Thunderbird entries in control panel.
            var proc = new Process();
            proc.StartInfo.FileName = Path.Combine(detected.installPath, "uninstall", "helper.exe");
            proc.StartInfo.Arguments = "/SILENT";
            processes.Add(proc);
            return processes;
        }


        /// <summary>
        /// language code for the Thunderbird version
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
