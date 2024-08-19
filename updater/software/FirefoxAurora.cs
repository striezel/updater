/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023, 2024  Dirk Stolle

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
        private const string currentVersion = "130.0b7";

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
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8dad027f23e9346848f6567de8bff81d284932c56c15a366bd869c6d138689dc60abcb61404b34e2dcfab49697c05e208bb7225e6adc34a57b34d27d26e23191" },
                { "af", "98c168f4ca75fafc30d404d79472c723975033d9572c333957fd2e1aea9e8e22095a0d8c6750794368a5f65dcc40fed20301121b44ed5cf31bc91d70c68c5f39" },
                { "an", "dc7c244985370577fbdbbe8402bfd01f68e9c93abe4927327e29ddc98283b18a565b111688a923d3b307fe43d07e13c6a0e94a3af8accebcd556377d3cf3e964" },
                { "ar", "5fcf6a8ed0f10f8cf7679405a92181887541348d482b0984821afb10d1f2e402f3829eba51bd2b27800575f86388f77d0b60cd50556faa24d2ce7942313dbd01" },
                { "ast", "36adc3d0ef250464dfceac81b214fde8d3c3a152f569ac55765fa7c8c885e5e885a5bb32a000324cfa0dabb93633cf6bea132890ff5d31fbe56cc8168196df14" },
                { "az", "a2926fb7eacfd699a28b8504955463edbdc4d804a1bf28cb6686efedd4b68b6a665351260bf05b061b44ed8fb7b66bf3d67c43239d5fdac1fdf42ff6ac5cbcce" },
                { "be", "c5bb62c31c600ed069d26784bc6f98af8a3d53083ff576f23dd1702398cd73e468fa3fdbf705a59e04284d11d569683e4668561d18a348e306309e708d1f3814" },
                { "bg", "6d0a0c866f088c55e0b006af92647b6d27829dfaf7ecc7ea1a29e18c089234b13710cc6fcf1ff55c9b21adf35cef4eb6521f9acd552f164fec09ee58f9549783" },
                { "bn", "00d062030f07c272a350d4ce7bb75c042c19059fb6c781b6852e407d1925ffcb429df1cfb5eec88b2d07ef5805b96b5be000a3035bfbddb1e3110a2787101803" },
                { "br", "a0929f49c5e2003a00540de08a50cdf27d437725a51232b821ce34075b175982e36c697bc1d8f53940c61984eaf0dcb9390b7c953a004f9dbbfdfe5b71f9d2f8" },
                { "bs", "87ecda37e26afdd8d8f31fba775370dc28d70b39e4b005da94e20fe7cf646a020b7ee061bdfe6deedd9f9757b84360972a68f1b9c917d86fc85d6ba4d5c7d376" },
                { "ca", "8252d5816fec934c400bdb70ae3c911dcd63e58e8630050b5e2797f10575483879d533489694585162f60bad50fbecce7104abf8248fbb1c65afe5c3e0dccae2" },
                { "cak", "8aeefcea68ab3fae8153fa2d6d855b7b0e8186e553186f4af9fb07283e37fbc5d5308bc684c21216040d40bee9e0545d6b84ea7c52a647e00fd8f873c22ac06c" },
                { "cs", "c6c274e1e0dee4613c1ec5819faa98d0f8eeebfc31bed7e153e5971b5074ebd5b1605b93c5b090a483ae9e4cfb5d9f2f840cc1a58d72a203ed74e3e76bf9d289" },
                { "cy", "21a62f56c76ad2c70a13b5f4a258049955074d31f717dade2ad4d7d3d785d6c68e40ba9674287f324c1535a9f795d0fc58b868349a8b31467e28a9e2d399d661" },
                { "da", "247744840cd495ba24226ff2c82c76485a5b7a8d532458f869d900710cdda7f72318b9cb870168266c468adecb13315a335c71fab9016c03a94f56cbcac0a1c5" },
                { "de", "cc330329b7cbe245c6c31e98334e91504c9dd45598f21204e25462cdba3235fb721957e736f6526b56f8e850dc0311a157aad036d23ae35badfd95483d001e8a" },
                { "dsb", "64fb8908b598cdf9f770dd2ee029afab2960bdb029a0eaff5fd681f119a77804cb2ed3237209730d2dcfa9eae6854453854d44eb2e81305fe69dcf04fccbbe42" },
                { "el", "f708ad8ed480228689ed47793653ac22e91fbac2eef76a578713ba957ec40f57c3d59278e55b8342cfd18001c282839a7aecdea3f48e93997c5a35c1da0fb4dd" },
                { "en-CA", "f34e5b94e2970e9d8bb3bab44d6aef539f846e0289517a699f80e96839731c46c9a788b6c1c46c89707e6fee663ed655a398f5808e9672de83a89cc6958e732d" },
                { "en-GB", "532b8028f76061368c328d8b10ebb2958fda75a5b48e2fee25d4ce1e620096215d0b8be12a5ce577f6fdf26a9be701bc553d81064910b81b8f62e21304537925" },
                { "en-US", "7ec066c0f71186f93ceffd8a967453f1e1514adee10a37ec74da14fcaa2a723bf5faffef106d2c3fe6ed26ee1131543d6dfe272008264fb23095f59d59c1c6a5" },
                { "eo", "e02e5e989ef8df20dc6298fa13cb3a1fd0590374ae3d3bebb630839c59308900ceb76b595cddd24886211eceab0d93248d2ba6aaec61943cec28cc657702fa7e" },
                { "es-AR", "9088b530bbec316a778e2e61bb2c80c4badc17819eb0131af6840e56601404409effa920bc2f8405cbee46bb4f3c6bb6ea00da6a7aa777ac0327f6ddb275e2a4" },
                { "es-CL", "3bd9778ba041e698acffae850082e47bab20ce5722bfa4c8798b5e8d2e2a2e9dcb9a15f9f1c1894ac370c9759a8af2c2d24b69bd0d4beb4947575fb94c88743d" },
                { "es-ES", "9ffe74764fd626df3f2e3915df504c81a59715f2837fc3c613a662dde94334861cca51780c73424a274cd89d3929f14bf32ee84f353d7149f236844459dd9bcf" },
                { "es-MX", "047f82a35b10a3f760fd81bb3c02602ff30b576aca6cbe6c4e8d1a40900ee05e2e3a034028eaa89df3cf7d18b91262df69c98f51c8362e1f25767e82d6c8b95f" },
                { "et", "c76dff3400429241fe5712d2ff803ba248dc54cfb8bce5959fce5c41a6071163ecda674db44b2273f27af43f8f1de0b021505d729286028e2a7d3e106fadf39b" },
                { "eu", "82397760f4f79c906e2b22abe42b7d0c42c236ea154865e8dbfde6baf5c137917d8800b901465dda17b9d9306f5e70e8916fa6986da3340c7eef396bc20ce85b" },
                { "fa", "8047c99ed4dae8030d2df22b1ddc44da9c92972bd32cd62b3211c318ae6a2de78bc05da7480c75325274ea5a3b5faadec34ebece620dc1ade6f589a037bf77c5" },
                { "ff", "fc7744aaea52d72a2f39da2c60aa004e4b1f4dd8e874fc2125ac656d568af4986ac676c3cba04bdb6239dce238ea6001ba96bd17c3d56db0a6df0607c704de16" },
                { "fi", "3f6eb4402d738b0c32eb83ccd801ca58393f29bd1210d90c5c01718425d10c867d34c9b517d93a50b3bd8737e1a2c4e45dea70d7fb4a8b7c0f0745e465de4eea" },
                { "fr", "ecaed8624d338d8bd46932bee8a63f4b3bd18f00e1b26e2e04b4c937d116889582cc22ced6b62fd20035c7d715a3973bc0bebf9d882d57bf3b91b81c0f0feec2" },
                { "fur", "12faf1b36f5fe158980c1b47de69c17f13309115fe41547f77b7f2b5f1470a7dfb9243d31b00a3923890f260134eedc8e1204b86d5e1b6f4300877ddee8bf47d" },
                { "fy-NL", "06838f530cd3a33b8ddb1f10265e0040108c5d131e337f62a2cf93706de5ce58bfaef0a2fe8ebf49c21370d0761597c4fcdbd1874f687945f1d879add5bed6cd" },
                { "ga-IE", "9a968ef88badb8c2190038b71126348fc9971c612b4675fa33d030c2f0722f70feaf72c52422f57caaee460c76b12523e9a94206f505fe15316e8b97acba9f3e" },
                { "gd", "6d804f72b30b7447da8581856797bcf49481389626a2f01ca97375c4d10c3170cdcb5089b0c8fbbfff00b2fc9a950bb0c45883c45e38507a5574d93d9c91b63f" },
                { "gl", "d3e2eb1f12f3e8e2edf312cdc55c44ef09c972df5cb46acfd287e367138e2581c825b9081fce7cce13946d795325b500ecad20d8ef90add96015f116589a1cdf" },
                { "gn", "ac4a04380164e967ea486810ea9ed2b5763bf6e304584d03b8f8a6ca427ca6363eb4e0303b8047f03081279e4def475b09e1bf8b8a727615cabf2b946b2b2107" },
                { "gu-IN", "86e65325e1fa62343ba86cbe8102efabfdf03e2eb9cbd1efc7850149abf742459ae7de453c5998c3ab230c0ae07bb8056bbdbb818f63c0d4279db6338db43e15" },
                { "he", "5509d530d2503c8cdb8e74e87c089367a0a6ae4eed182e1d8bb366a649b80c20bc2b483d7360f1c0ff3f29ac11ec7e56122c1c5000aa8a0bd76212e3896b2577" },
                { "hi-IN", "6ca3e552bda588338f5aa00ecb5fc41771d94c36f061b027a6ac322e77993893826455a1ec467b8f6f4c2ceb09e5e9cceb8174a80154b5dd0aa15af491c141cc" },
                { "hr", "db934623c091d2025c237caa895e1a62874dc901be340fde34b1ac8cda74f9a0ba7f059b0f2d8d68d6145afd1ffc4ef9705bbcec6c1425ab2f58694f447f94ca" },
                { "hsb", "48dee5adeff60913d1d68d72c8c61856bc36847a884fa776d2a80f4112063bd0932b103b75c755118873d20115e3a9b46c8a48f66169e87a336482ce2a332b99" },
                { "hu", "08b0e30d62d5477a6a99648ab5f3748e7f8e9e882766146909e28604747df09dfdd5d64b4e6c102166d58e3d3235676ae73e6c944c5cbe462e2c4a3fab62008f" },
                { "hy-AM", "6dc01c4e61754a0b794a0c785255762dbc2dd46ccba50e0a4a031fe318f1b2289d73fd676a6d0b8dbc5f56aba7288ad04b689de914d775edc1831af850530a6c" },
                { "ia", "1501992836004819f3389737e06b0a4d5ac370b509a60c881cb8dc1452d0de79ce4ecc6049b63552953869cf3390b93c86f626e3bad662c0dce8a9f3f3a45bb2" },
                { "id", "0cbb4602d951fbc5fb02c9e750ec811add205c63f3882f84393a55957742dc2014fd0ba0c1aa440ffd77a0ef23ccc81b42c756288383fab84889dc1e1ed3bc6e" },
                { "is", "6237db8d58b9f36d5321de96a9c0143f648f05060d790e9a44dd8d235b7061b0e591b9de191f90c8739264ba86ce46491ab9e29107bd2802fd3373b860b24a17" },
                { "it", "9e8c167c9d4f7c35bc6c4c809e2dac96c8ebbd3d82e4b4149c963e364087778a2c410b1f8596877a444facff2064da771d996da4d21b4731348070b7e6f7a132" },
                { "ja", "14ba8217e8998a76725681cf85b06402761edf8e019780dac0bd126515a4bffa221e59d64d46dbe740c8485f244e554fab4a52ba8ff2f10c26bde9e1e118a21e" },
                { "ka", "9d63b087e047853389bb35c1bc4e9296562ec15f1d29f1c828ff3db374066cdf97a10843d359eab700ef64a3980872a32ebbd7dde9ce83639bb6d5f086c95748" },
                { "kab", "38e5ad1220792d0054d6879fb1865bfb4876e30248d7c097d6dbbbf41b0b33b55ea13d34d77e0007b82927b13ae4f92c57cf334f8f6b20e7005e89503e43499c" },
                { "kk", "61e284fc288011e3c647fc2e34768af22ae3176f272f07d28012ff074b21fd8ba1617e2e8eac92dd4cc2ce328b5b5bf50289d2a307237528b568e5c28fd9ee61" },
                { "km", "e425f258c4fee80b3148626f6cfa2e34eda198bdb6d44f7ae4defd23ca2da715a6ad2327998d3ec8b43c32c84785772bc12fc92010d0e38707a073550b29c3a1" },
                { "kn", "16e81f9c56d58d3289634b2ebbd6ec6ebae138a31caa0bf6501b8c4612e33a5f37feeffa20b76fc97ad750efb85c7d5b49adbafadf666ff01a40510d4b4ce1aa" },
                { "ko", "4bfb6dfedc87f153ad313e83ec6ab3e41795c2aaee784a3d0409ce46968b0cfd013ff49dd14b2c91f760b771d552d70365e47dd9873b71bdeb32a96ff8f66a71" },
                { "lij", "93200db4e2b4eb31c07419a0c15d71d1db84b2d91a20373101bcdaf3f3b28760d0f2b71a973a533587f6beb9e00033c7e9dd406eaa1bbd11d777d698716b736e" },
                { "lt", "7a5e3e3c05551afc70d0ebca0a47da3673cba1fe46c6911f88793a3e89d2b59f42b085c6c395c717712f54097d54a0b2681c842e8c41c409306bcb02bb9b6cf6" },
                { "lv", "3d0966719d32d6cd85b9388ca27da94568a72a6e7b22c5dcfe2bc60d056e9cbde6429100342af92c0a4d472254446647747c5873d42665d786a8672d7891a706" },
                { "mk", "53091b050dcda83b95f5b2e718991ee2ca48e6c7c66fa0903d2849dbcef1fdc76845eb81b7c740b4a2eb864e098f2108f72d7889c563c5d6e7a1e214872a65e7" },
                { "mr", "f11c5c823e7df1841053b4f31f2cf789d53d6ccdaa09a32e483ebc86eb7ebb7bf59edabc7d857c9ca02bce77ac9dc484beb176862ff9dbff2c8c68f2d66f2395" },
                { "ms", "f03c986f2029b2d6b54c9f95e5e24043d7b9a2d2dd29db7c1fbb6bc747e02a6c88ab1e95a556b67e8daf5c902aabcb80937666acf0aa6ba5a026dac180794cd2" },
                { "my", "ed3293adc8fea142bc7b902f4acc6bd9130fd34b91e6fa42102df192428dfceec405ec5a988aeb523e519e44e1e27fee6e049861d76053138381df89b49aa242" },
                { "nb-NO", "cb4cd9d80048ac3388a2a7f886013b10881d390e8f9a2d636fcfc6803bdce123146ef5c6e9ecab34aae15130094173b3f9557f5741b5730af25918c2d87d2667" },
                { "ne-NP", "acf5025cdabf0d456dfb0f550ace3ac78eb4fa5c88c2f141177df3271a7b9ea37c9df1b77319e484a383520cd651cb09a1de55af1a77f2dcee5bdcf1679e8628" },
                { "nl", "360decf91d31848bc1b8c4d0e59071e5bc3e85543fc9c7a228e7477188aed408df6eb87813841f6598e0dc42ed3cfd35878d8b86ecc5869a2192f59b37321f2f" },
                { "nn-NO", "26dc3950ac617422ea6e1de81c014c3b31021999ad544881ce617f98bdc024df32adc5ec41e895b64e329936927d7c1616bd09bed7dad26655a991599f39343f" },
                { "oc", "380e0d5816ecb3aa85bb24121c91b22904b7bae74ae1dad648ba3bc40bd3b023fdf5a29fcd2b6019ed955160a9cf6edee9b482d823d327649704c4d0b0a444a3" },
                { "pa-IN", "63846ca3c336d95603ec561af7847e97f877549c4f70b055d1bb154b04c4e0a4cd4c27a4061932db2a3505fc8f15e8b047e53c5e4f9e5bf38350d69caa57e45f" },
                { "pl", "1822435b69fea60e6b2e4ca8b17423818f9dac20f04bc8f06dbec8570f3eaa84a3e62840a51c238776caf69e54c9b83211e7a86004aa30cad6566861439f5d8a" },
                { "pt-BR", "a7b9f3d27fccca3d8f99f78c1e9e5de7acbd62bedfdc0c07a9a3a32e59fd719a4bb4400460942f84a8401a4e635e16f291f956352f741074e41deb7a78aec930" },
                { "pt-PT", "197504d2738387aa0d856a2302e7cbbde9467dcdc48379d894052cc8026d97cb2fc0aa78fb75936e7055df90404df958f298839c5fcf2946493a772e2024b166" },
                { "rm", "f44c7723c3389b218d77e5009c7d9ea465fee4b5197540b5ff151b632c379aa0c676fdae8af8e1c2faadd29e4000b24f2c5f8ddc71d77b71e37e5ec63ff16461" },
                { "ro", "1fa7ce58b8a390b9b61689478a19ad5a44ada81521308220a910f77bc11b46f793005b10d0d4100fd01125ac570591c3a9a28544e934837bda802fe66a113e54" },
                { "ru", "5f50e86f5c65d5c1f152af5cf84c7476001076e95862ea31d65a560d20c2fc253aa8cc67e3665dfcf250b39a4c8745d37d1458a1fcc572c9e299195456e6255e" },
                { "sat", "afcafdef1dbf6b553ffd6ad98b5056fb634d3d97114be238a6f25581a50e4cde8a9b24bd149fbcce698b76846d4fc12686f46759c7a8516d6a4c681e10b22ec4" },
                { "sc", "4f3f8890f45e1adf0ee3112777c5e9ec5861a64ddf60ea0ab683efd5a2de671e1b6ceea65711afc8b4b296a7af65f319f61273468bb02dd488053072166e78ff" },
                { "sco", "cdc9de0f6295674c84cc51c56e94ea82520197bfe2d96852cd4cecba745aafdcdd03e36143aa56f52345a3ba50277fc55caffdb55f0d0ab9821f12b8f536b62e" },
                { "si", "e2b2b51f89e73420e77232817ba5b3338b8b606fc1cc63081165f5b56bf5aad61980f07b0b2060c7646c204b9ee836f9165e897bc97796008806a6cb3fab1ba2" },
                { "sk", "2c7d4ecb338c8247c21994f59bb19bfeab4b7850920c6b1b6fb536281a996ac017f40a1658f9d6035ac1876cbad011f2174f61672fc52498599d0e0580ffee1e" },
                { "skr", "0988ef4cce75b12ef0993a5487838accd039a92bb8bf9b0d4b3f7dffd2d070ec5acc3e9ff4a913835b8d5ca7ccf8d66917c8694899a9918938bae13da24e6a40" },
                { "sl", "10aa1ec90b227dce498953baee42a3bb1273dcee920f80f33aec0defb989e5265074403464f410d5ba93dc8299a998ebe87caf82738fee391d07677404c6be8b" },
                { "son", "1c6175ca1d88a8e11f809ffbfe961cf24bcc07d2ccccb67c719a5b96632eb53b65c89de5e5d783b7cf795ff7fe28cf6e0912ae9ee08f03ad48968a42132d851b" },
                { "sq", "9c3c7d43751e38c65005b8846dbbc5a82129926c9eccd331a6136f76784a8a519fd7d0cbe9e61583bf3774025350df18b1601580de30b5207c68dd967426cbe7" },
                { "sr", "747c35eff117f815983a95be6ce8c06bf1718306a82fdd8b754d2ad4252b6f5ca55c5d1153aa55ce833d1846da648e36c21493f5b31e3cced9fe6b3ac36e00a7" },
                { "sv-SE", "2161974f32ab0bfdf6102e6645d217c89b99e203aa34964c4e1e3a1a62007cbbb2d122e3bb3bebae68fc78d09b803c38a6118c2904372b64b04dc3032af33099" },
                { "szl", "d8688ed82b13bc8f1cdfde4e4d69ff8c7c24d93473d8b7f8dffa6ad62cba09e80e170301b5a55746d029e1247321c7b83ee2a1d7cc4008760ce88634127a2c35" },
                { "ta", "b760f07c7beb8a90c7a9513077dabc28abdc1870babe47352daa7dc34c35c51b955e4c6016422ebbdeca96e31859665aa91e8cf4d379b73f5a6d851bb0d0efa8" },
                { "te", "042240f3009a8c2d8078a214365c3d8f32f8650bfb839002b6c811f2499f5146a7693ddbdd56921745f65a1801c29d8da327f0a22d836878b11ba0ba3db6e9be" },
                { "tg", "195a8afc5dd5977546e48077bbb4e037fa2cfe4d10d574b75293745b081802a006064d2e3cb42384017f96c8a3b1cd63977c10a42af5481db20ae8e51d404fbd" },
                { "th", "949a3657f3567db8d1d7bb3bf9bba964802fda0836debbcef46ba5e1a1c48c957c3327cd3b0cd6bee9648fa55dc6d0e73b35f2c2490858d560d764446eae440a" },
                { "tl", "7df4c16ddf59e76cbbae7ada7de1eeed6d8328f00e4bbb93e5ddcba805540d6b5a55e696b0f0e1a62373a079304f8ee8d917b3213e68db14204248994213d5ba" },
                { "tr", "80b2723922922a92e733f73ec1d0e2fa4edbc0b3987c9c03c22fe528f62f1f5e717a6ddc3ae55e46a12f75f3c14ff2a126c7be97dddadbe59ea374ee852106ae" },
                { "trs", "60ec6dccc6bf7e684c3019cc5027779745f40c15c21ec2528bea7ca8cb7f15a363ec2561c8b67c766e133eabec165d7f209c0f90553bc95d08185296d68faf39" },
                { "uk", "90a9dc435102cbb74b2a3cfc7ab118b1d7343da6efbf3a07486edacba3f44b069a230ea0ff2582246a5d964ca9757b91ccd7bc029414439c96fbf871145f2100" },
                { "ur", "85dea198d18129817c67a165bd7df93a2c4e39da4f6aa2259c1f7e063851844b6e72323b30a9f5df6f5dc9e90021912133a9de40b685d5b231233122cb65d27b" },
                { "uz", "89cfb379c54f0961922cb85b338dcad65a7c0d1792e93b7a0f80c48c013379c262718250b774af5d346ea7a013dd4f44021567c79b0a6bdba2ce44ca803fe766" },
                { "vi", "ead0769ec5422ec3738fa7567b89ce137c2806b19a33b84aff142164edc1d7ff6adc429e839c9795b692a7057d5563a74fc1d4c1fb3b54cf8754b4d53f1219b0" },
                { "xh", "988a574cd2ba0083faa3a08c691c798b583076a28d2cbd41d19fd06a9135406a2450b376558be71c485292a2e2d588e8e9d8424f6cba8883d6c7ffb9b5a20ffd" },
                { "zh-CN", "fa2cb17101be284a1a7ceb7c9a77f51cd4eded2e44088fc32664096b63254fc0e53ef9a15273ff56759feff35705d8ed7fd1dacf68422d41bd066354cf2e2ee3" },
                { "zh-TW", "ba7e208bfb60712248e959595cd55ca2444a0c8550e8ce6373661a9646991955e5d818aec66c6d7e1056aded5de1519427cad944981f485f4a292713a0b7e691" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/130.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "f36c636d97dfaa8ac734e4e721a460132a0d179d50b4b4a65b5c5668ff4cf7339951ab60804667ca1bd6f7394a3111f29c7e638d6803902c24cba5f3a6e9ab49" },
                { "af", "448a74575972e64ef1877272b63fdf73955ebf71c9a84c22139ad09e5051d8bddcbc344fb631594affcab0250870564e1361670f260d21e698c242a3af04ccbc" },
                { "an", "09c5fd5aff1407083ad69528f607f1ff3b51e49546dcc205ed22ee0d2ec23936b5c4d10d45e945244d90d332444d2335b9bfb0cd861463457babc29e857f5952" },
                { "ar", "35b15808779ac437ab4db39f5d7b23e83d349af415e2e5ca33350b97b6fc92327394a7589de42e40013ad6cd65ed18175275118ca33a49355c25347e921f7167" },
                { "ast", "615e3511a5d5c091a8cf97137245ce9b82bd9eb805af553adcc936effc7d30892d46acb0b540d4991cf18bc755997cc35444fd504938da6af328764e93c9dae4" },
                { "az", "1564142d5ff60c94fda52f8ba2cb54436f7965cd2fe1035676491e9119938977d5a5a1a3ebbb7068211ba08fbf1b3be4b014cdbc710d98ecdeb46f1d81d0eb4a" },
                { "be", "0738b3099137c338b57c8071252dd0eadef4924b9bd3e34af76c7f3878740242e5944a7905dce29471e76d6b6d64f8b77b10dd70e9d644689a9bb69f0c89e725" },
                { "bg", "e611f19d9d85c9b0d2892d48b6d0a2215435faf8cb779e224ceb038cdd5a04a8a4b4dcb704756b66f8f2f4452dc777cf353ce8e1f530f6435685a81bc76a270e" },
                { "bn", "f2645213a5dc05204872f3f22d1c48d5e3f2b7c6ce0c9d4343a1dc7c504d68f58d925f9a1f196c950929cc2ccd1066db323718df1bbeb5e13e6ec806fd53d94f" },
                { "br", "1e70677b13954f24da5e931477835e4950a1fd350643155370857488280535c4c49a9d1315d0f07a496c48d0bf112a429b44f93ee3cf0a445673eded08b0cbb7" },
                { "bs", "a138f1e36c91e29740c1922af2a5517926d912c2a4695b3ea33dca0fd01fb35c71c97e61f354fae27b4f8ae7fdbca8fe1f468d3b25527ce933327ca1e2ccf45d" },
                { "ca", "53d0b179e62eb0dedda83d2e12c769d0151724ff6f97a013a545536054b0b3a0aff5933646a0e3ee22df6218ac1d46ac9fd65edd094adc1ddf76f21571477250" },
                { "cak", "1fb844b7c5832220f797299876309d2c8fc09f5ee377d7a1cbc612465cdafdd96adf3294017451d6195a0799c698c257bec5083880991187ee8e17b1df4d35ce" },
                { "cs", "b07e0f9182762bfa685835524440c9a0ed663ad423416987186a7274544f91bdf2aba715bbfc4c42018208e7b1ef9ce3c75b4da04d0bb5e1a82d632b4223c792" },
                { "cy", "a150aa839bbe94c8f622d440b503d692695f36363a60f68a3139b58279da77b5d7775830f618207ba519e985545d720e228f6436a89ff4dcb025ca8cb3af2d9c" },
                { "da", "52080e06140f72e72f074132465157242705851418f3ca3fc2f83db24b797e16e32e1f2137ded8223b55ebb9461c6b25dca897cce89afd5766ead9ad659a7cdc" },
                { "de", "86f48b59a6d4410fee32c2d994974b38db5474d69a17ef5f869cf452316b5a6d24e21d658fdb5635b8dd3fb64cdd35ad5a815e51f04d733f760e46aeb0d80514" },
                { "dsb", "9dcc039b1206a1005a5324eee7e4f94561c56726a8f572483aa7d496e0acb9dad9429fe8dd0a2ee48d3fca4de52e0a4565d22d95b353631e6e6a7f770cd807c2" },
                { "el", "ab1b8a50a1ad3c3d3d094ccc2a65ad77413379429a81e90bcb7f38a2ac77ac93cac380d9af756c1069a4511197d38048e5094d6c5970e7ffe5d177f0d48056aa" },
                { "en-CA", "292ff56e4378427a519b51de9cd4d44513ea2c5f108337107a52274a4a849b6291408569d15faa69405ca9f6f513eaa8446e047bc43649a1eaa6f5a2dab10f5f" },
                { "en-GB", "b35a09ae33614e3be9b65f434ff81e619d7a52d9a45614b7e06c9d75cd5cee73033640997cbee02cff34f70422a429088ae4732f045b171141c539ee87d29251" },
                { "en-US", "bf00c316a305e0672e34e1d4ea4bc21d228320194407d1401786da7e8c6ce4a0ca7a9c32d95fd7b1a943fb41025f3d217ad3b1edb6746578c517bb8682179591" },
                { "eo", "cf48835a0614f7728595e17959f82e8311bdbffd96229fea9976df4946e0f0c7cd6def3f3bfff1bdf1f7e3bf4f4c63c8014e3228260b2eca5233ad697a569edf" },
                { "es-AR", "4e0394602be736d5311a8ac5f9dee354e5845ee9008b364c352959d9188f67d36e4a1244837041bb46692c824957d595a126efb7f4fbe0c0f8478670689213ea" },
                { "es-CL", "4a4b39ad636038baaada55edcf5dd5a5a6420268121c52330be61230b85a774de8209d0b13e7b8c71ed3cff93ce15e1547c7411fd9bada1d92c137241885bf43" },
                { "es-ES", "26b4221028ed7a8368133493e75cfe0536aab8ee3529c332e867f14b80a90da4bac7c7be3e31c8e9c28b1a71ec220fde301dc4a0dedf87c759c970370e8dbc8a" },
                { "es-MX", "eea15b5525f3b8282a59ddd6a5a19a8daa04294daae20a12c1db7fc69cba3d37ebc27ba99fa2304b5635307510ef1be9b02979d911762c05558dc6c21873d57f" },
                { "et", "fad7de0603a19a4cb0a2342d9002cf8eda05c01970cd67c057fe08a88ba0886d7b887d88529ffbdf693f9bd32513ecfef0c1fd62b3c613a17335a8b950291b3f" },
                { "eu", "37d438b172d20971bae0c368a46219402b4aefa443807b6724e364b5bd46c789fa90b256016cca50beb73762efd7a2818f573db604e39388f48268c3a01316a7" },
                { "fa", "04a3781f4d59ab6cd611d04fa3227b782dd511640d1821f8bbb480b3a5c9bff6d7df9e37efe6e3b89b47c33fc3f150c7e7b600f0bc3d4d8c283b75c5ee4febf7" },
                { "ff", "073d6bdc6fc3f5009967770e4ae9ba42989f6e00a6cc2e8792087f3df39677208a3138ef5a229105dd6ba396b01e35757660871f63e7f0dbd1b97106296a0b47" },
                { "fi", "0438b1d45acf4e6d6254fb30385f3bb03ed6e86891c0a9aa6ba8a982c6fd20c56c42f3bc39fef6cf977b0251876afc4064cceca6083d21204ab50cb23b8b0d81" },
                { "fr", "9f296f445ce1f0281d717ec636c5ac34ae3640aa4ee36be76cdda03b6be57c767f73ef77f19860130bae92de50240c5ad88dd199756adbb5c435577a0aebf977" },
                { "fur", "96e2d9f48290dc6d9d9d65ba1b5a28d9fa8b392d9b583a3d5362fc2a0a1a9f53e9ed9f5e9879f15500f3653f475c911da46f75215935d503b862e843663b6998" },
                { "fy-NL", "7a3f9009712baf67b126feb4798be7b12fb32e80bcc338e36c692308284734c3d5813b7ac662538b945473a9489f34cf5a49ce25b6550dae81e52003e418616a" },
                { "ga-IE", "575f6247c28ec72cd8a00edf6e3f43f762ff02d2411ce7204658bf6493f68caf7322ef584f8caf588bc375687fc2ab9607fd22e13550ef69ec2fc9e7f6d9123a" },
                { "gd", "eaec323f300358d0cbb5723ee1455ba99305ff9a502d29ca5a2a1b5cd9ab07801de564b5a4f40d1e1235f2b44a95ee3a4160c1b12d9d697d018cb4ba388d2ae4" },
                { "gl", "ad1fecea95e797660ed1248ff742d1b5aa789c322ea08a80dc29224e39e8f46d781512c51f324f3bda4a23d7d8ae3f136ff14aaa0f8c96f501cd5f5f4cd72cdd" },
                { "gn", "b2baf49739222a82a4ec74f70a9c16ea831d836f008d6c432d88fecc9486b552ab33411d2525e786f7f4c94ab12fe5fc753e21de6e9e137beddbd49f156b7353" },
                { "gu-IN", "9d94ae5cd2fda9fbee4f702324acbae85860ae09341f4aac27be274a58203eeafffa0fac6a20ff57abee7d002d015c1ca8ad428655b646bfc021a180df1ac111" },
                { "he", "ebf0131ecd5167645ef00dd422b702dcadcf8d00517464a6e36d73c82cb681f3d853066e330b2f21d653657638e1dc28a190f8cc7f06c59b3ff117b0f559b6c9" },
                { "hi-IN", "139bd0f207074d9775cee5cf05a9e8c67dc197adaf36eb2b0bd42cb2cc193d7d3b2bdcd26ed6d9b1d18e718b83656edf39c8cc9a9edf899f4ab9e8d004d15c03" },
                { "hr", "a9e598d0e00b1783740309eb3285d6115758e699d320b249a3de741733292f77dcfc79f8f463675ef6c16342fec9ce202558ca1848820ca29281138f01a734ef" },
                { "hsb", "cf27462ed8da4f573c22d69154fa9285b6a655e3032501f6d4d582221e7495ec9c4b259f029eaae9531c04391c9b45fb2f8936df0d5386b54d31f949353fe8ac" },
                { "hu", "b1bad2dfcbcfaee6a64b900b71641b242f0273307dbf51ff9940266b5bbe9bde8c496b3f7cc6ded2e44ac10aee1d2d589631426b842c3865c9aa06a941b2697a" },
                { "hy-AM", "3270bf4e8c4bd7dee44e49ecad3a4aee45453b800a9dae26d05eab4a8c1ec3221167a2433ed279814363dc238073f916d863b43eac65e2c99737dca4a64001b8" },
                { "ia", "ca4ebe547bbfd56301a2b9dbcb6c720172bbe5106c8e86302e42b2a3047d120ee0b17a7da18a623ff7a91d8b4d09b2178d3578cc3dfc0210e52b8128647eabd4" },
                { "id", "0e92af3320d27b1f31fd2a7367e8ce11333153a2082ed3d36486d2faec0d960bf9ded2c444a86291243141d14510b388fa51e56b8debb6e9bdc3f0f100f77b9e" },
                { "is", "b8f17e14b3f5e1d41276f90bbb4e1e5cfceb82d91c6bda529f5148f41a1fcc48dc94c5e0cae0b0471b8ea408dd5e1a0a3971309a1f757815f78dcee63d8f2cb0" },
                { "it", "fe3b67552caa5887ca61f6c7fb91c101cda193aaafd56871f157a7e2a6c6077d1bceb7444690c1acf9286c50e4f7ab224a8f9f2ed92d7aa1c7a14709901accfb" },
                { "ja", "32dee50f1a77d6bf0938fc0ac5e7cf195a1065f798fbe9e33ad5e21cce88aa67b52997764422ae3958a5e9598e869765f231e5fac71b0a42c4024f773f522961" },
                { "ka", "15531370c630a133356d556f7dc1bb32ce4bc63d93367c4d72d4cddd48f8717b1e90f2928d780eeff08684714a926e10290104beb7acbe7d093d1e20a30dea79" },
                { "kab", "d556a0147820e4485988328a4a7c9816d1daa0d5d3b8ac252c23f2106745cf16681aff52eb4a5c4d9daf02001d6be002ca4c642ddcf1d640a97870af3a2d2a53" },
                { "kk", "ebad137369b7ee9120222abc309d3c415bd75bd4ab126f45e6cd79dd3c72326806b98d682ed61b5fc21c64b63d7ac3c735666c120a0a257cabf233becabcd94a" },
                { "km", "61b202f7da844a8a0a12caab3eee2f87639d0023ee73673c372a33c36047f761fb6c74b050ae5f2a875654a97e507647802789fe5b14306926e2b99931565492" },
                { "kn", "2d5c2176167ce69feef20faa0d89403fb65e85cc421c5fe3adb49212fe5b99cd0e3aef024864f61ee7d3215ed098fa95754b773880cf8870ac186e4ab5177070" },
                { "ko", "21910a656e455d5d77850eeaaa18847bcc3d7cba38d9286a5116ba9b21f7588276dcb387e09c47b0601f1c017ad3891c67a1b501cf9504d064dcdbe6308af5c4" },
                { "lij", "00da7e07eb89196616e49a55d6347f94adffee60955d0363442bedd3021b7a819a08d8a1be57c71e02b6774e11292d7f210f896633019c21380aa75bf5f7da92" },
                { "lt", "89f59f46258b1e1472606763ad23c105dfd298ef17eb893adb12c94612ae6aa32027c1357455db8ba7efa0b7c1958fb155900276de953f38ff6cf13e5b9b4a40" },
                { "lv", "959e1a29dcc983458dcdb188110dc310a942c691729a25794d04e8d4f9d125fb53558a2a6d9fac9d0b55eed194286b51212a1ec188f36d02725a90efae70ac9f" },
                { "mk", "5e28595369741e21cd587296154ae4adf8bcb9f1c788213f3646e852b1bd18e2f9165153c3c267387867d9a5755b9d44f773242b976eff34fa1b0b0ed578db8d" },
                { "mr", "93f5bddc139241f7a8a57651cccc08c76f8bed05fc3617fcce8e0fbe3d5334d32ee711bf88288a20e82505a3439f7c68f211d0e72dd97c3858e2e5d15139371d" },
                { "ms", "c4ce63700515aae8446b9aaf53a087c2602424082e2b54e7ed62af0bfbdaa7df12bf9db1f4e23dad14bcc8ebebbe3b1a491eb50ef587d404614d4e0a974ef3e0" },
                { "my", "5b86d3a1702279dbb20def4a4c71d4d1eafc76a00cd853208c3174c90ddd8cd4eb6d1cdabaa79e2df57e07b71a16121df365e0b5aeb6541839bb675849525b1f" },
                { "nb-NO", "1bb7e26a9cb3847efa074e47f43ffceb2175fcbbd25213416f9594eedfe99d1541ace35271550ec5294fe507fee09e5424b9a354baf684d16b74b9b22b20939f" },
                { "ne-NP", "cbde4909fad300414354e252f68e37f2abfd17914578a2e689f76e5b8e3034a7b531476a1ef80b6a7126d6a03898f3e5024e819f4d3affa2f5dfa15a9121c9a9" },
                { "nl", "e9ede9a374a458b9dc10b63f253c9a21489376cb260ffea3c7ab0b91d630a421be001cab72063e714a6d0078f320909f20f0fed84a8e39a8ba98ff7c15bdcbd7" },
                { "nn-NO", "edb75ad7d41e1701b982c931ede4db38efedb28be341921ea915a7d9e41e2641d741ab8e9a230093eb1da3154e343a4be705721103b7413137d70ec652293f64" },
                { "oc", "918c3ed2f6af0dc3f6fddb0572e2b3a2e69cfe830ac673f24c5d5dab627964e5a5e3ba45b367c2cf3b5a959884ff3f43d803e488476a9aefe2bb802e4a34f765" },
                { "pa-IN", "4dc64b0f292af0b8fc8ca756326e0eb73605555caf4a7bfe0b2c7f4079d2263c7af25ecbfbe787d9c16af99c94d66bc581bb4611038e4277f4cf37cb2970897d" },
                { "pl", "8518793a874cdc0da840b72b4b92333d5f3161f4c742f99fedd25ed2f6ffa8ac841ab1a6f6ff6dbf6a1ec5768e1ebe6344fefbd658b59d26d9b7ee2e995fcdc5" },
                { "pt-BR", "9309eb0fca90c244502594917a92a34951dea6eb681b210072853973d42da6fd6b490b3804dff9d29a04082bca8da3887196c9dedd6cb731a9c97067db81dbaf" },
                { "pt-PT", "909ec107e0232c999022df1cac9bb2de471d77183470b942bf41730dd86ba19c8a3c844913c6eb0a42e28a456dc44f474f972cf13434259386db87acdeb70542" },
                { "rm", "27eb4d8be0145d2fc90e3b6e0959ab2d544e0a62976ff830c8f8eccf6798b5eeef502a5813c75a709e4e6e764bcffb7f9d5fa92a84052b23f8c6ce42e036b7f9" },
                { "ro", "d04d79adb4e14ffd5b99bf82919a321baf1eeb0933f6e5a373d72da71bb02c8bd9bb71f8844ba97a33fa97ad666484717488b0094106f781464ee4bed1e65f89" },
                { "ru", "8e1cf7997aeeb933096770a19ae97b21f63c0fdcd029167667443e726e403dbc5e4f07a7d5f5f9cf1a7ae4d688a60034ca6218708b27dfdc2fb6f8560f6930f7" },
                { "sat", "ffb66e3262b3e983c8d56025ea56d0df1e655394608a7a5b17a777e5107cfa06c0bf22a821da83ea746f07900384acd058d191043623eee972f15a826c2fdfd5" },
                { "sc", "2155c35834d945ae706b7d2cbaf8d22c806d6784953d54558388507a073f6a7b90052b4c1b3cdbeed05bed68cbbbeb93a2c6f1c3889652d51ab2d74e148a3c35" },
                { "sco", "a968b479885ac2727bed0592e77924b48f879ff9ce3e317854d96ea11a8cd75d2789cce48096081646d5b6906e2cce685766ab24fa9f03bdc89fc0487a81eaba" },
                { "si", "4fec6b3c301fd0900d2b688ca348facc24e577a1a79bcaef26d2dfb226e228a17098842a48de9ee0887a6ccfd8d2930ac8ef31f60522c4c2f5350eeb84ae5c4a" },
                { "sk", "86e6ac494ac3a7472b22f9e322169b974a4589c0d8a4959475b3545ec8c5de0043f9fbd0786176c8c18798ef7f3301532c4c7601a7747ac57aa640d7db47636b" },
                { "skr", "d0e454cb7e52b9e26ded20b5466a8206e011aa2405cb35d651e29fb170a6f7fa0400bc7397ea2e479f2080de74b59b1369a8f22302a3854e4eb0ceafb08e15d3" },
                { "sl", "acb50578e7067b76a9aadd43153341d21dcf506909841375ec3e3e67533cbf10a4e0e117ed2d291680f4664e44b94b7905c48a77926b2e3f566fa9857f7a37b5" },
                { "son", "89a84938d3ec21065351898998d2a6023bd0bf56e6fae03e09e583c572f65fa1e5f2efe5630d6b1c6522b23d8fd1ae3d267365b8b61ae93d0c4f13317e92b864" },
                { "sq", "f7408a360e0d226022f15dbc8e256d3c9e4597addd15c45d82c083ef7660db8632221c2ba8881e5ef156c9fa49ce1cd2bbe7edcbc1919b25ebc72f8991623779" },
                { "sr", "3c832367cb4f9d1ec8fced7a4657c56ae3b8c6faf7b6c7b38cc354e2f76261e1c738c5744a7e0f38766136d295e3c1fe4c2d5cfcbdfa0306d6de1fbe8d207a19" },
                { "sv-SE", "fa5c247c1ba1136b3effe959fa3652db317886888079a5b0ca6a11873baaa9b9a20ad4b5306a166923cc1cf5813943882661bb32a593c177b1b98ee1f344775e" },
                { "szl", "42a00cd12d6f7eddc409acd2341b033f58f64988ce7006b5edd1ae629adb0cbb371798eadea3639a59c96fe68634c1d039196dcd5fcb7fb43072b97177ec93c4" },
                { "ta", "6177472d3b3ebf31e4378424054c5a7ebf62d743cc4a4f6f48762ed2e2aa00e1266fdbe43f1a176cbb59271dc0bda3fe740e49926c83e3b07a5e74b1cfbc3867" },
                { "te", "3adfe8f3cebb0886c67334efda4a58819a4f812e9799019b14a63e5cb40d234afe0cce1ec49d525d593e6b3f7a5b9405b09c9b6da31545dc78bae6a67767dd5f" },
                { "tg", "34376ba8dd693437da06305742ba5b684c685e1f3058897df256454ce617542d16052bedc4e6187b22ad3eb1c8a648d80c72d963a540b90c26155b47e0b37f02" },
                { "th", "a57b88fc1395faccbef12ad44c149235e12e70afd1193f4158150a0d3404173d045494ee051e843a1f53a42f181c7cf0864ccc9f8a26e92e1726294ed4e7ecda" },
                { "tl", "5f1815f81e87db7b96fb8b3b1de7a932a08403f6979e0b47d44be2e36e7cb660fa8f12421f2f9f55fc12547fb15f29635431dfc804940ca43190d0eeef722a45" },
                { "tr", "a8ab3b7e0d8b79004d200d8ea60a95ab796ae5aa1f77368b437b9d47a6ed4c9f982005520c2906769d0f4f86ce40e3cd81bf1da3fda24d8e0c80f6012c1983f1" },
                { "trs", "769df9a64fe302da4fa313cf52dbb8096ecb128e4fa103e74289bab69016ca2b3f85ffe0eebec3890034b923b37464d8749af87d72497fc31d7261a4fb05c63b" },
                { "uk", "c67fe3c64624d4d010bccb471f440bb2c5b6428d5285e7e6f86471649fcffe424bf29802ba72bc865594ed2119efb4254122db4dc27528111724666240191d4f" },
                { "ur", "3a0cacc2f479be13621d9d6713e327b79e2d4dbfd27147ad050f0af78bde5658a5ea728147c35a9f539ea04e96a2b0580ed8989555e6377a16a4cb016b43dde5" },
                { "uz", "da9c0f1d93983b1393c22843ab21ae7ed7a47c43a98db5c2ca6f8c2f5902ec9605b2f1e073618af23661a1c2bdb32a0c631b97be63c2d6e86e6a33c4ad65e84d" },
                { "vi", "f6405f1daa5dc39215a0083ffaa02609dd9e8cd6d75a128e7678f5b13bf5c5d0f0e90d525c11d9aa25090a1d00a32edb50b916c5c1710264ef6b1a2c71a7cf05" },
                { "xh", "e84730fbb8bb3697f4b7cbaccca8c3e70a3b6e532af347deeca8f20716172f9a2ccf838331c623f50f1afd8fdb914b60017f811a6d586286d14223f0e7048186" },
                { "zh-CN", "eec8f3ff1734857782f284554b79376795e2b9452cf6db1fe1ef591164bf74167a7198e57c344a7d58fcae9af3a44922618db1f53db6a375b9c0a9e52962a266" },
                { "zh-TW", "e11d2fe6ed393110b3df0521497486f531555af9b021bd27c4017f63aa2efd42614231f4fd1b19945c026ac8b8657fd6af470c57b91415ed870a89b86d509411" }
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
            return new string[] { "firefox-aurora", "firefox-aurora-" + languageCode.ToLower() };
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
                return versions[versions.Count - 1].full();
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
                if (cs64 != null && cs32 != null && cs32.ContainsKey(languageCode) && cs64.ContainsKey(languageCode))
                {
                    return new string[2] { cs32[languageCode], cs64[languageCode] };
                }
            }
            var sums = new List<string>();
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
            return sums.ToArray();
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
                    cs32 = new SortedDictionary<string, string>();
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
                    cs64 = new SortedDictionary<string, string>();
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
            return new List<string>();
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
