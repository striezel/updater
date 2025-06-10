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
        private const string currentVersion = "140.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "03db290b681ef68454eb85e715d14069c5dfb00138aa33fbdd6670aeb81d34d1560c6f7f59c89d7145e1168654001c28a32a9e32c570ec0c1629122b58b5fb77" },
                { "af", "fd9d9aecf351e9e65e44ff8c74233c65649611af4a2099934f79f61e10741ebd4031e235222daa4566ffe4700052a2d841eec8d1ac269d3f43118c52217ba64b" },
                { "an", "42973e48bb0ee79326fd9d3f5d12a3b5e836dd7ee97fed73d0b32a5d839efa8bf9b478d462a6ff321f2b9be9240134c886a2cfb6d130672743a268e2e2f21974" },
                { "ar", "89e9ddd5c621542a9b0a5cb444a76a54ea71e8aaad03d107adbbbe49ec5ae817b2d4214dd0b91aa32d6f4f10a63b1f4e6f8f40cc95fe2b58723a0573cedf0b89" },
                { "ast", "804cc70f602e1776c0029ef4a4d00a6f3bf93e7c7e74c7c504bc8f7644ca65198aa8c874b6b55aab0d9bb72e298982967af13f953807a38727ba453e4952122f" },
                { "az", "149349625a1fd2671a32b55b7a885a089a9a2808337cc50a61062d1ac4132a8471b1617f0f82ab3355bdc81293d0b65fbb3467f4b5379788f93e23d97e24e8f6" },
                { "be", "84fbb06b26eb1998ad9bd042049db3d82650b4002c4f0c1bfa91f6d181ccd40b11af2dba137aae034d31d33925dd122262a4306d61b3efc65ba05bea711f2da2" },
                { "bg", "83be70c68e2dc2fc3800ec8eef76f06f437fe8ef5335bbbb2b52536983f8ae614e9ad67421233f48476bb26dd9f4c0d59e92c14522299655acd1fabdc6cd5bf1" },
                { "bn", "3597d8e2917a6349466de7ce3b1f4ded49dd8d0ad5f3a0d5bfe3e00b8f99a2012675a9970abc6fc6238b8e61cc6b9c6525802a171499eee8a1570200a49804fd" },
                { "br", "2af2a5347decf03dd503770d225a8317b59080bf167c8367f8bb8e3d814a43b2c8a878707610e748197e5d4f0fdd77799128ac2fc640170824abef596f3b7b0e" },
                { "bs", "ff0a03f56bfe8994a5072e941999ebafbeb985d6631a42227fcd002352dba424280f5ee255b0e15751f11beb7aa0fea0fa83a2b35d8b5ef9f85b160e91111f0a" },
                { "ca", "d71342d954d439e36c050e7b0d779acb44976d012ce46c7f3466798e56699690ab688c2669cab266007575d2786284cc4021ae672cde38acb0323e3da48d5118" },
                { "cak", "5bd4f81d0d203e063900c6197b4e048e0f22f07c1438e6bcf144ef8f81c66cfd9bb592ce2c5c8a94cccbc2b952ebc9d2cbb641679c5dd312a1bad6dbb079bc51" },
                { "cs", "65945387d91657f4323b6a664ba5afc7e7e1f27481eef52576e4e28c185a222925a497fadc3cc7bacdb6586d2cebc5e291c0a77c2674bb819c640a46fe154476" },
                { "cy", "b6d499b69421fa1aa1e545d652f74267c0afe912df578d2f23a6de5929510bea333f35219700aeebe07bdcc7f5968df9817950754abb5f18eb2d3b9ae676bb86" },
                { "da", "69721ab67f28e1c316f299ec74685b354edc01713d29b01c460efc292ce064a64d5d76b874be4a7361d6a6dbb743e8e5f8ea8bfc49b2c9b9dc84ad8932a18504" },
                { "de", "1567fbfc74b10ec75db54ea69002cf7211b64eaeef467f6dad519c779a3e832fc1c85ed4d05e967deaf1ca5f07516f50f99ffe9fdfbc20313fbc3078663b8fe4" },
                { "dsb", "57984a9f3b791c74ca3e8decef15163c9dddaf455f325427a855cee3f0f8d18988345c54ae4ced25c9324efcde4a6a1a5a9b7eef7ad8c2b678bef244bf553ade" },
                { "el", "05da86972719d1054abbc779ca3c65ac350788c2d39fabacc29d910761a95048f40414518578256d60e578204035659f85d9f3bb3531ab2d496c580ff2a0d724" },
                { "en-CA", "21d4d0a6587c7cc5433f269bc4aea12876dcbe61ce24bc47f9e00f04b655088690fc0e0c973894f765f18be96b0df63dbf681a8490e91ea2ef67366cb759ffa8" },
                { "en-GB", "b8b5b9cdce1dd366ebf57e70b4706e106ac96d0971cbb71395b85e96c10280e55ad97d234eb0e325491c26e75f16ce9a8fcdfac34c1cedc612e5c66646a947df" },
                { "en-US", "60df3532310f4880c99f5b20ff75dc5a0a565b610c1cc68fab611d15e7025f5baf9686d82280b8f1a4c1091b8b938f19dff358898cf915b2d611c648845e7536" },
                { "eo", "91aeb73b05930eea302802b44be7eeee97f8fe8c9142e90ff6494536c426892908db3e7870aaacb73245cc0a1490fc659bb54426fbe7082e6d33b51fdfbed677" },
                { "es-AR", "36545625349ec9c5c7751121141417f256e7777d7fdbb8264301654b6b055216498e0df122e02929fce60c526c639d434d8a4b26c8949846aa8a579d99d6988b" },
                { "es-CL", "b49790293aaa90952adfc8ad84be27e37572952828fc0a927b16cce10dba60f21f96b4e01b152a5316376c20670cd452872f75f1e9a514b0e266d21906ddd7fb" },
                { "es-ES", "8565cc26a4245e6455a53e8bf9954723a118299de11ec2dfb048c79be6d69f0476e2d867f993a97b3d8c89bddc683af693932bb25d86389f251a9edf5526914b" },
                { "es-MX", "a72cb102f5abb1e5d4486a097c734ed149cd913ea8f4b0d4654102eee9bda10b2ed290eb0a56efb623a33933f693f5526b225c584a469ec750eabc53d40d0a25" },
                { "et", "a1e518b4f484310415e7d8598794ad30bc30e8c8924265b68f6f14b6cab0a4553bd311ba8e527597a73728426fa25b988d8b1da608366b45a177c39c05cf5805" },
                { "eu", "44ae7bd1e4e41f1cf2cfa78e13cc0b772b9a2f129c0bff36b41449eb4fa9a61f3657170cdff512490863dd5d4840d49bad39ec54fe4ea49fa388aaf2e277301a" },
                { "fa", "942c912a01329a8140dcb13fc625f2b029b41bb392e6fe7ec262b1ff2c9ba924ff918ed3d21d18c226bda0c75d89c4ae1a15cf686aca0e05cde822a8ea9d3a39" },
                { "ff", "d561b350197d7d4d615e2f6d20e048ebe200a961434eeea16dc991b33c42fdecacf69d546ddbddfd1705c9d1956ca46f4061d84f82c3b667c034b49377527144" },
                { "fi", "2e0e892af5dc48dda40011f6521a2ab54218c81edd606cfa6855dc2b7eef822616adb44e81d2317875c02c7276c331ab5c9947783e2b25ff53ecb7cac6c6f586" },
                { "fr", "0eb43f2e5562d81ba1fd4f2aea1579cb0e8ed2dd2e14986bd9ab9af72a04f9a384cc3332310575584c61999119ba203a91945fd525e8f548beef33d8f4aebd2d" },
                { "fur", "6c6ee6077021dec1115ca81a5eb1445e0a1f148809707f131fec86c8e9572dcf81c4d7f0546f99b60dd9bb5571336cf3577723da259befcd00407a467db33c96" },
                { "fy-NL", "0db7ea1cbabdb5b86ff0b9482d807ec6f4374cdd1045585b24d6532abdb256bc8cdc7fefffb294c5e0e03baa3b17ebcf95cc292488107a3c630776c20c2c8905" },
                { "ga-IE", "c198a2f7004cb612d6328c56c02b9f76071ccf9f6dc9a7744fac93d66b1ea56092db0f1533cb1caba39613fb6ade213ab28ee3e5d2572fc239e9ddbbd8fbd2e1" },
                { "gd", "fd68399a7add33505a7d1e1d0c250fd14766f37b936a5c9c563bcf9b0dde56918bdf0e4528efc589f168568d99159e915d77a49d501a792c3c5a7050f52b01f6" },
                { "gl", "adfc866c1e8f54efaf929b760c29e32d6c680a8bc422c01e21ef3cff43ef4eb0d3ae2158d19374fe6baf6a8d0965357aff745fb6ad1f6b778063f3f12a6940f4" },
                { "gn", "62acd362d077d17d94e2e828e7a567b9d58e85c21c440a3f893a40e60c8bfdd9012da7b24ab4c46e8ac49e50359c148ce01a365fc1b03126fa5b47d578b55eb6" },
                { "gu-IN", "ba6a7ecf914071a59e575b5ca01ba8bc69e309e80b36f2672efed9e8931b1e32f65e8519c5713dec187eee9a6b03c2e018481bf4d6dc3ee09d10be5571206221" },
                { "he", "632d1608114e503f5ea8a18a2672f9474b29860738175edbd32f1965e7e1b3433d798650a130c890a2c5e7922356a1585a9780648294e5a3d65612e66d84d227" },
                { "hi-IN", "6d5b24d2bf8c00cb0eb95b88dd3567ef986c51e385fc4679ada6d0f6225c5913c1fc259aeb4d68418775c2777214b35e594e6e5565d8af7af158db6fce74f56d" },
                { "hr", "efc771ae4f39c4e31955eafde44b5b999f21bbeeb27ba845a42ccaff189f3a8fabcc7e9aed5f258f8872d0034e58f1d0010696d9b871e8d6c0a601a662bf0d84" },
                { "hsb", "ceba1461aefeb39cf4901dfbce4f548d54bfe501d790285f8521d20a2a4a1375934b126ab6d7d1c6538b9f518960668c12af151dccb24f3cb18ccf59d0551ba9" },
                { "hu", "1f975a889ce030606dfff254243b305c0c2127bea26b45c7e7d6acdf13043465f02b0da791f012fd60e164d377d68b46cbf09609da7903be11a9274fc6b9608b" },
                { "hy-AM", "549dcb64be26240f8047d0526bd98c3f4bf5d2c140918832c7d214e2b73600719bfe548472737890a1485e900e7ae48932b2df2cd9e9310660310f0fd9694f11" },
                { "ia", "ff7da60c5762f304e93a16c66ff9a0d27524ea98fefecd052b6b1df52d063be994fee711ef4c92d49f2f57113cb67a0327ccf286b79d0b9726c4e216944b4990" },
                { "id", "f4d59ea68005c5b6edff6d16d3a475baeaf413f0544502b814aa14db0596f5720e3d65f069dbfafddef1f6ac2b2d4e79f3d3bb9a4b9a72ce1c4151c05bc17f0d" },
                { "is", "bc657c7699e348b86961f9d5d3fc8311a7f4395f6a41e70939da9acc17a003b73eaf4471971f404eeb48e657b9e50ab275ac13660502bcbd94ddefc7e4dbdba8" },
                { "it", "978197fb303fddd1bbc3785ee5d8bc115f63bd60334c7369f124dac1fc2148d82d3ee9ac2bd2d15261136d8c7004f5989f4da0a11a7035802b41686c3d4dd5f2" },
                { "ja", "2f999943f2cd8c43bc16dead731dec8c84db713b62e16ad83904258479282059c387fc48af420aef0f6f04ebcd45f61260e708de6e5f67c6764a336e7fc5f7d9" },
                { "ka", "24f1aa4d53af84cf6f7d10076f6261212d2c3a6809ce070085436c36c9788db6506a8617d1d33d6f7c01fa5622ce31cfc6964a378de657a6a6d51d23a3547822" },
                { "kab", "d4cfc4f3039eaf985a54c86dfab48acb6766f97efdc83da4efd0bc499e649c8c4e40e3ba08842d3fc75e234f309a9de1193c5361197696defb29362cc8d479ef" },
                { "kk", "4ee56a8bc08d3728370f93920a279396f7d37bb8a38eb61ec5088e2e70834d280edcf7507bf4ad668966fe73ca00ca1a0471700650d846830c389e8ce3feb117" },
                { "km", "7c7fb754e1a158c3a280097554bcf8e694c731b7d588a8ef57ef4259c9f2ab2a79f511900d914ce2f303750d8ec5b6200365753c054fe0013631e79a3e7fa792" },
                { "kn", "4ad23ace661206d22356f3fc3de52eb7c4f2a68df19a8067c571527da02ba7753f72bed3ed02c43838df2e04d82a180779e17c2d8f135e0cd25ac0a948406114" },
                { "ko", "c98185f8c96bf0250184abc2c77acfc179748bcca6d32d2cd8da4e80c5ef130ab66a631ee187b63fcc5ec216eed4a5cd90766c5135de63be98c4fce0f1dcc3eb" },
                { "lij", "9810d3f48fd2340620e01ddbc032f23f1d04cd6bccc65030c6d482fa1200e1cdb12ccece1f9bbcd909a8ebed223bf9baf838be3b69a5a32681ff6e124c459c71" },
                { "lt", "2aa54acad868d0915e6e1daded4bc758cdc0dc3c06620259ec5efb96ad7aee399071edf2b5ea1d1542f9a1d3e90e88bf4583d596fda7b81f32205c0d046cf380" },
                { "lv", "ba21dfea1daf85fdb48a2a91af003990470d891d49b646d393ce03ee48d7096a81c985f4a7742932d8fae0cccf0318b2b45a9c828373759ae7132dd50a935b2e" },
                { "mk", "807b5493e65e62c91eb9a1b5bb1b26634bd672a918fbc51ebe184903fe7d394b849937cc689e12f3577d095699f092d0e13f505ddfcc045761a68e1be4d6ff04" },
                { "mr", "3d7cc9ad101d4154c7c8c5da58542cf0b00289033b23e10adf9d5197840265befc729ac5aee2aa1e961f6999cbebad80a7c01e3faf03025210494e2931b8ca06" },
                { "ms", "ccacd2b6f2889eda21eaabaef87c8b310526cd4e9687431dd331eec1455c507c8ffe7eb4bc3934c4d5013fe1b6fe4add9ddc7d50220c3c7aad7bea21d8bc8448" },
                { "my", "4687775b0d310b3ed139212fbac8a612a909eb3681e5a6860b958ac924689eca1d6dd07150903dc811ab40394d8e66bb753c6745e80ad037e62a3645aa92eabb" },
                { "nb-NO", "de433b0b0b73e936f9df9d34effef3e93b23f7619658050840ae0b1a8b1cc9792a7db90dca43237527aafd6efabcb21bf1f89d7fc39f6803963cf0042702b680" },
                { "ne-NP", "b6a5ab0a56e2299db7e91f389a3b37701cbf789ca6a0a3e067407968e1536ea763d264740590d6c5cbf25738c9fdc49de8da357ebe93e0c12172627b34d5125a" },
                { "nl", "a32439921635a96f24509a4b8e19054980a2787df263e185f000b66220e1c71a193b3b2e71a4d93dea8ba3cb61dde6ccfa4b288b8736537e0809bc999ee0d80b" },
                { "nn-NO", "daf874a09a386714098f47fb62dd6451173cbccc95eae45711a042508ae06a540325885b90462e1c3b19a5be42a95e176d9bbfe1d3d092aa2a4c67bbcf131db1" },
                { "oc", "fe450893fa4b0a91b778e8edec8632818346c800bd8d736f7b6b427bd69510d3d5a029fdc48d25910646e3ea5ce205a16b418bfaeea1a7350729883185c0acd3" },
                { "pa-IN", "4360a92ca111d8bb7f85562b7cec4a51e134b75ec16fe03538b2b73e6c2bcdf950d3c7f7689fa7f94a3e1aade637ae3c8d5547c68331364bf2a81d3e86c36495" },
                { "pl", "0c7fbd4a840503e9d649362190d5c36284d6859001b5c904695fdc5ae048a224ec916610f18b86e353c1e4936a6d6e9d55f5a1ef3f4ef231fffec0a58fe886f2" },
                { "pt-BR", "c84dc89b9306ae140d31b0563d6ca7601baca089589d1b931b76f377a207ec1f6d65a9a838fcfb7a13528104fca3e10741c85fbf3261a08046905578304314d9" },
                { "pt-PT", "59048cfda74b9bc7e3fab157e58efdd743e7a6c81030daac5dc134e6ed59f02ce85666be01c0428b13920e476ace5dca0b3718e70f762728fd12f22d498cac18" },
                { "rm", "2bf839b95085d4b90026f466dea9cca43a2f828faadee418856b87a0bd57f11e07c6d940234d78c36f325b41c1e912b8d9ec556c3fe9c7e3a9d050b66eb7fc26" },
                { "ro", "cbf584e3a43c1a7301ddb3745515a8e1101a2939c5aef7beba80521ab4e4c048a3a03c34463d0eab08342fd6d2236cb8956089d2f1f8c52220c51f91f3954255" },
                { "ru", "a6387e5090d51173f641835da7f1e977e8277f875946143d598b1c6bcb1282b34320af12dd2add24627441a4c218bb7ee0fe5a1e0690e7de22bfa84b9d96875d" },
                { "sat", "31f0db33e6408efbe3e78ea410282bc6500e135e936d564aec6902b5b2b293185dd00e323873e2db19a1bcb959cd175224d3a63b0108da5ce1b674f1e71a1b3c" },
                { "sc", "608e17e0867b3eb82155537ec847ac9fc73702d16e6c9f76dbcb089bfec634dfbabab0480a76a014ff2416add7650e00366b826cc8085eb228fcf85f176a2ec6" },
                { "sco", "6476d4194588d0885669b9881894e591f27b9f81c5fd9798dff6d8510faf0de232316d744af54a848581ad7be373de0398a36d65e74d106e42ad49fcadcdb71f" },
                { "si", "07bd548a21cc46dec671e3e85a25f4d43eb2b8bcc22912056d8a7f9c04f4e2fcdf4626912bc6cdc02aeaaa4f2f077c9465822f472955d7489b76e1a3977af65d" },
                { "sk", "30a5e6ae2ea2e2bf39b738ce061ac749513c31d775c1fe5884caccb49396abcbf6fdcf1c040153843a8e16d7c4fc6e0cbfdb101a60adc4b1cdea88153518861b" },
                { "skr", "bd73636e06ec3be720a9553c905c8893efdb180c4c5c7409e0b5db76c1a999bdbcedbf04874e570f6eb4c99763bf486800e10fb1b65cd3aba470b93b721d8811" },
                { "sl", "596d961ee340a5ae46c230bb5f3b264f2e149f5fb04622f960509fa282d091c72adf7be3f2bf013d8ab89a2a7f27a22727e756e680b8e2d5738f85e1d28459c1" },
                { "son", "69450bed59a3961450b23f70a5ea60aff528ced1f92c837205efd0704eee9a5191b804271a6137aebb541044b85cb3722817006375c08f58bf7da6203821425c" },
                { "sq", "3e94bdf650b132310952781dc00ab1d8c75a7af9db89a6d1d1a25e414518bdd90117e7c70fd34ff4013b883dbcceaa6db2f6d4bcea143b8ef0194c17ec32c816" },
                { "sr", "b9b9cb7e8e16b9e541eb6fec713fef7e61ddbc77eed8d7f61f9c14964c9021c4fcabd4cd12c2f650f41b673a6c846a05a1c6b0dc769eb8e45fc6b1cc35c4a4e6" },
                { "sv-SE", "7339e9f7aba889716e39a4245367d2ee14ff0526d1e438c2e44e590854087ec9e7488c20c3c9e97fca0a2bc0ae0d5b45846c39193c268cf38e15bd2d8f7a1193" },
                { "szl", "77418d92a972f396072169786d2a3fa4c2c09e4e52b312a1e0de7a6f811bd11678436d2cd5b28126176e84760d5400c0ad3c14b2a20fa79452a9a68b66d8ec67" },
                { "ta", "66df5194d597858dea12eba13b04e994a90fdf26359b3cab0a479e7806141115f045906313220e7a395be643ae1ddf5b6b5cbb0c246cc8b8bf09749fb2616e65" },
                { "te", "298776d0fcbb3b6cfaca73b0ee53d003b8af3983e1d2966db64129a6aa19e5e46b4a62cddb358ebe6778f5de33c59a59d42ecac205650b0dcb2cb3ef8b841be1" },
                { "tg", "dd06191bfd9778adbbd3fe3e4597ed819bc81b2bcc9c60140310a5462f850421ae540a7a3e91a77dc0b1309db55c4edba5485e58923b566618fb218896f3e10f" },
                { "th", "9aca7e751fe902719152593f89784a18f50f3cd6cf875e1e3b63e849b44417bd4134e2cf9a24f21e1c641d37b6e6542730700eb570bb3df85eace08a6a148234" },
                { "tl", "c57feb2ce87378f494df5530146d7c81b6f1ca0734622b415db6bde32db4a8765c7aff7e6b4629a103c66ca996d7a5b554359ea0552f706cd3f0029e0789158d" },
                { "tr", "3a029b903d06219380e5a89e71d56a4739da2f089f7adba50ed2ed11ba17d6d107ab2da85fcddc7f28a921cf70d0f4bea7100cf3aa89f2eef34ee6afcbea247b" },
                { "trs", "6e135541a953f0be5eb6a890cef70e2e3509e2240599d5d650f807b30c5f5664591d3c24ece39d336bf3715dd662b3cfb7bd373992da0b7d3a1d7496cf717d31" },
                { "uk", "b2cb542866853139dcdba84732447afaefa326eaf7c044b2f9e8444718ae3345622d17ea12f0611f5af52f8f018bd7c6fc539fbbbeea345a01f2579da1e18a44" },
                { "ur", "4f3fffe73556881f48367c6b072177e4579afa44170d6efa68f198dec3b5022c71d9d26b5ac28f63b993525ce4e4e8f12ccbee5f5d13e87bda0a529c11d057cd" },
                { "uz", "f5ef80ae2563de2042f9e0a45d8e436b9ab4a443390ffc3eb3b4029c4de3240c300eb145969fb0fd21cb7af7088c9a4dba3a4d5c35e369fc46fb5c626c76d41b" },
                { "vi", "2c688d6e814dfbd731b69b3597a0e4212f578098624f7d2c08aeb3f966ae2db10ef5c227e32b1e1738f3bed586ea7495c5fc097c8273ee97357e1553376c97bc" },
                { "xh", "e12d59ebd1c9faaede2091203cb5bd015f5a4480c682d1633999a89238efc45e014766ca6737e35f589ceb88d2488a3a0bb434793f9e0ddbd4ba6d692cf9c547" },
                { "zh-CN", "89b93b4bc3f5e73bb4053fc69d83b7d4753370efd09e77fffd1bbd1b7262abc85a2658ea5316259bfb0f4b60ed1a95c5c478f7c1a605e27b0987625c524a610f" },
                { "zh-TW", "eff541c44a2aae2a661f1893e68c50ed14d7cd7b08bf931a2786a933d0d95c3620b324844fdcaff712718099e2eba44d473ac483eb19d117412efb04ccfe9711" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/140.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "12ad64b4b0681261fee3093009e82e85908dacd59a78b794d36cedf9baea4cdd3963a3510edf3af2ad1849ebc0013fa2271e682c46fc735ef04e5f0b092a6024" },
                { "af", "cbd563ccbc6af6e316031584e075359c2406bb09d3aea3951808dc3d865188cabd1319591af752de173dcb18ee015612c83cb9ee8d6788a8a6a286decc2f42d1" },
                { "an", "3d616c5e9d7013fd2547a2ebac753f2e90a42061968b3ab8d339f11d1632a5cfea5e5ae45510f7b2be4db56184229cbcc3d499423d57335fc43ed683c70734bd" },
                { "ar", "5e971e310b39f9062181e54e89cfec9346be872ce1da508465af0591e8c1feb9761bf0f38f6b154e955cee3ae0812ec9274299b73b13bc37d5e200663ba13c47" },
                { "ast", "1b233baa03844a2a35743c9efe7e993e361da824fb1a738a40b8e405308c14dacb695b03016f8c2dbbc5be00a412568f5d059c433b279feea961445241c5c5fd" },
                { "az", "875c1d32d084e2a9ff8daf6f496faf7ff5d26814ab229240e983b8661a5161490ccef16d2f49370cac9b7bd5a2ee179e9fda8e89c3015dedcea1a38a34870e9e" },
                { "be", "dad37f6e71f44364153bb975b47696ba1f92f9d0320fff54b696bb62087bf5ce2186a470b3b9a838826493bda6d6d6fa7983594e5d32d64e821c43e302b77aaa" },
                { "bg", "49a57d5b69429133e5a16b62f51aec2b4a79acea39f7812c6869863b223c54fd0d70f50511184097d5e49e80ce02771484c15327927842760b79dc5b3202dfb1" },
                { "bn", "d33cf4c0936945dfeff5c93dd528f8f3c6877ef7747b3f5bf13151a4de52cf66aefd5d0bb85f58db56314aa7bf598891b5609a32d4896a162edfef3e30923373" },
                { "br", "7364a16f1be6150fcfdeeb2cd4b2d065e0b7611452d00eaa2673ac8fbc8631e4e10493f83858a004bc464d0221f8aedb20f9de87df5899247eb271682ad45781" },
                { "bs", "4cb90638f8ccda1c989ac23b4aa557cd74c72fceded93d2ed511867150fc76e6e67e403f3b9deaa03e2ffb1a06394d1ad64b6be47878a910ba2449fc8c24befd" },
                { "ca", "73032d2fc806b1bff6b4f1dd68a5c4b0cc057d7a2b838a9b1d10f0a1b8df9052d0689c586f59436e4ce37dc30692eab808b66632e5a2110d219c85494632ec87" },
                { "cak", "8af1f39ce8a0ad57a3a06b576e2467ebcf5624c5102cd285c09a188b34b95c15859f19893445deac6e9d09d60ea7c1a96ac4147b2df6008ae82ab936afc86229" },
                { "cs", "5068269c87c94e207e5091f0887a72c50fa6ed10a5cbc5ce0fcadaba6d6587fba9c49cf4a846ea967776aca0678cfb9666c3d5afe083df323fc609655c76b2fe" },
                { "cy", "74587bbb3fb2027d4a826e68859a3d4656c1199b2b84860dba3cf42096f740d5f46a08f068702b60d3ba9ea6854a6cfc515957d33104160f918fbb1e0f941125" },
                { "da", "69328a7103589bece68554b9ed425abc007e28066907c0b38fcb05ba7e0aec90275d6be1528007731638a174c5084f05c4eae06e83deb5db14c2b7cfa574af94" },
                { "de", "bdcd54d0ee5023c5d0b92ec874503671dcafd2e8fc48ed40ae7ed4e517e25158f21a802f3fa1533700205be4a47455bd8bb7d393aa611819872c6b2394c34f74" },
                { "dsb", "8c71871c9d31c70b8cf54828abd74ab95b52b4384b79dd2c3da6d5600c3ba89660d53ccd691377a41d2007db19032c83447b111b01886b3e0fe9547d06ea2ff6" },
                { "el", "202cbb1c1d33aa47b6955f1264b56f98ee50b04d88ada1f14ede3b6efd831b8f663fa1d9feceb5c78af836ac45567eab0690b59e053fc130bb7aec07077117dd" },
                { "en-CA", "a70218f378eef92c739f0b76f068f081a11f5c53727c3695098617e68a376396035abccfa81f7251e0f7ba019d75f465e543fd960e5992ab6737827184399465" },
                { "en-GB", "6ba5d18acd2658d595e6777a9e5f07c9abe13d0ffa79fec03bddb7a7e7cf97f0b907b1e8b67f0c209045ecb74ac1da39962be92ffd9e0c6a252fb997d39271fc" },
                { "en-US", "2f97ce011261a3cff5d6952d80a24306689785565683aaa0282517900c2f893c490d77ad0be811e48b9e2e91484ba3ef452c0ca78cabf067b3f228f8acb280ca" },
                { "eo", "edd34b72f09999fcb96f326635ec14e422846e07a64e19d6130ff556297bcd4d9202303d16e8a1d6e85203f9191be77fbaa923ea778d0062d3b83c9ac6a44c5e" },
                { "es-AR", "fd096d0b700b045eb33b509ac43a78ae8736aca0fabb0f4c0beceb1bdebe978f512f755fd5e5c8ef2103e513d78f12b30594a04487bf4e34ab8bd5924cf5d229" },
                { "es-CL", "c578418ba40443e59120d6b93fc4867caee1ea3c89420860d71fcaf18ec7b23c055abd9c6ea766a1fb38c117d412f77a4525a463d30f6d181ec6c68cc314d933" },
                { "es-ES", "fc7a3df07c76b071c50c2014a77a156d791a2d425d9524507fc4efc8bd5235ec12305438252ca606e35131ddf6853bb3972762dac45db0fdb82e876631c0795a" },
                { "es-MX", "98167b657724d600144f8a51b09bff94c00ec3f723a19a465724a4832867cd98174c6aa8a263588bcc8e95ed87856bb6fa40a410387c65c8a05668a139ff6d23" },
                { "et", "33bf8fe0b0f36b8288e9790d6003411fdc4e5905bc78d4409fa1331c82048e8f68674c071611c60ef04d6ce0a18a74cae16a0ec605e451399aa1b6c43d801674" },
                { "eu", "400677bf46fdf13fd309408a318e5468f6bdc586503063cf64db969b547fec4ae34cfd5cb65f6d2392ea12ac90ed2b4e70ef2fa521f3c97c7675e537ce6e7470" },
                { "fa", "adf705a9e3b5f744798b34a79b6683fc35c71dea4e52feb88c704899061a4e4d4f26fc360e5223993f6d561ae228ea7fd56782a4c1a38487200291315ca652df" },
                { "ff", "c0b0d4730a53227fd270220ef62790452e69b4358544c48af26a9e0935de5ac93fcc90caae0c5d652825def7b0982d972c3a21c3fdb130c1736fc83eb57556f8" },
                { "fi", "c7c1f04eaaae536fb6dfba41f819b9633f09c7d0e73934c2b09377ee3a07bfdeb954abb8965ee42792d388d3847487694756959e0fdec6ced2e808c03423b31e" },
                { "fr", "1079a9700becf0b6ec5c7d24d03fd82ff2ee26d7d2a22e0cdc9ffc5bd4928d984299c1e1bac134b43dad90e386fb3c764240a9b70e0b09b3dc73e29dbe5fbe27" },
                { "fur", "6ee1d6a5112ac1b4253d879dbf161ce64aa7b1293a5fb319e28633a6a4f3d6ed1664d20d52b6102abfa0e85c6849e3b354d01557b2639c4eebd750cd67e5966e" },
                { "fy-NL", "0cdba2a1bccaaa5ee9c9192b850d9d06eb47cac0de479edf3869226d1579ea9943f621f6e309d3e3ce8183f64056f45621d31821f861905e93f2d5416fdf5dbc" },
                { "ga-IE", "479cfd6aa315b56c5742451393def1df4e745eb5fd496febff91ada407ad8adccada5eadf5c99d68347131dc73a6bc3bbcd8f60eedf4080655a238259cabbb3b" },
                { "gd", "b76fd82926b8465bb26cb00dd64ed87e1302f674823d5b0b6c17be4b402e682ec66784a30b73cf4270eae619a5f54c4eb0cdd4d8ff2f0bef46d95f82861d5b85" },
                { "gl", "ce51d18491771c50ff5475ab6c93102ed52ec1e91235e68ccbada4790a9b4a518f9ba02ee7313e24de55808acff7986f3a63f2e1958435c58f817afab53681ee" },
                { "gn", "eadb14ff3b818fdb1d4cd42fe013b80f5cf270292077ae8447ac15639631f065922425a2b087576269c49125fab2d859984b1fc2d9a893b5cfc8ea6e8c768b45" },
                { "gu-IN", "40e1b1cafb68fe00a37e6bf58f9765db186246dd2b4dc3caef3a603d9ff197e022ac4e7675395d6361419fabfe786a4400fdf91ccee984b3441960538e4bd6dc" },
                { "he", "ba3aa241994af76c2ee0a42b612071b36005a04b782129fd136c3b7ec301d08dde013e21aad566857c397653c335c64fcd7eb4acd1d716ef9fcde10bc89eea33" },
                { "hi-IN", "89e844c1bd6b34141170150765e045c8ffdd6b52a6e655284c3f649bf25c970f6cea2e0c8d1073946c51de9cdbd26f025965d60a4daaff14ec37c2d106f68601" },
                { "hr", "a0dc8065135d6a90c2d98d1baf768137e845df4ce7e73a827eaa5673589e99a5a2433280c267617803e8fc9ab14519d632849c72bc2a06b7d0be9f30f2d4f068" },
                { "hsb", "d8b1f6df908e05a85503d73827dfac4dadb242203ab5085b2570cbbf8ebb041336390075f7e4bc4256d3ac7754c71a172c49ff6b1afe6d501b7be87716b163ab" },
                { "hu", "06eb8c848674a38c4dee3a82f821e1e32ee49bbf1e9601cd39c4a20cf24499d13d0610fe1d6ec5ab6cd65cfbd8a22ae7e9be5216014a4c55595bad037fc930bc" },
                { "hy-AM", "f65e7477f7b400b8bbe842822bab2b232a89bb72fa8623999b293b6368836dded5e1e24db718b52dd0290df15b8ea523f51e0daabef7bc43f13be2286acbc8d3" },
                { "ia", "2e95dc53fcb1d1f13db05980ba95425bd6fd7b094e52bfc55a4e81a68b83f9c3dc6785decc6ab34f0da6d6b06394bad9d7b52c7d708058463320dba52606841b" },
                { "id", "f339610b5c0ce4456ef04503c10e646b75de71f4bcc1275cc8181976b63b08e8a517a6e861762b7ea740c41cf6a482ab01a6033214f0e33452e74089a10a4d55" },
                { "is", "264125766f08452ea9f2e68cd455e81f2dae6fc5bffeaa12ed568358e5fe1a365293fc88899db4b6c39dd65534bb81f8e9cbb59060c22b841a11ea1ef868ea0b" },
                { "it", "eaab481c3386f788cf03e82e50d747385bb1cf1f080e7ccaf9c3832578641b0a76b2a09c75ab89d2507e32569adf6b248266cdbd7f4e379e2ee4288feb9b8778" },
                { "ja", "b0a3e35e594192602e2263f4ee28ade41e5b897224eaba56c40018d2edfd296bd4196213f6a35774bcfcf5dd591ef991a777fc90d2533e78dc8f5f61b1e10aca" },
                { "ka", "5edfdf7f12db1b1ceb791b2dd671796add3944bf499359c76204678f52605e4ee0242c0680b8d78ee9c8c3413485b592240c545179c7472ba1d25f74adf6ed37" },
                { "kab", "5947feeac0ed92437d144473ace93111178df1650cecc22a2588383f608906ec7b4b3af1a5ab479d666248b39e4c6512bb10cceb1d4f30ad9fcf3b22d8fbbe0a" },
                { "kk", "a9f01d3536a1bdea84de43dffc335eca5c180ff645bcc08830faa7446197e366ed970b33a1c09d888be567d51896b308f60052ecf3329997aecda2d1f1b2a96c" },
                { "km", "7fc09a013d7b5fc660559096e9741c9909bb33cc97208a0d248eb8acc7b0f424cd0aa46409731d799057cecbec2f1f029c3a5af62a1e86ace67b6ca989e141c1" },
                { "kn", "697314ef940b912725b6a6ee901903963bb9c8c5997c758c300549f3f487c81aaade3152219aa575c9b0eb32253f094a9808b041497c9b07fffee343962505cc" },
                { "ko", "02d5e0ba1a95977ce643a295258e9e3f08637508f913b57ecc8ac8b9bede4fb8e95577a63a705b3c7329cdd64a49f87c4f5a10fb9121a186d73d851177fd827d" },
                { "lij", "c67f15757837e69cfef7726010e7093e1989481c0102cbb58f15f1afd1aee5dc83242fe5e9ede1ff9fb305e834fd6dadde54085ce5b3b4234d08ab2fe8cfbf7b" },
                { "lt", "78890f8c60b8c44ee6c2a61eea162bb342f015326968b66a83f6fd0cefb8a7858f0a38bd8250454e7e028404ad8dea9ace886ea95beb7471172754b7f1aa6302" },
                { "lv", "2eb951ede803d4469a2c547437a58ca1027c645dae29ee9719df41792d6712196b0b6fa395e0b3c20becc70f63c7af4156cf38a28bf99e3db48b8f1fc2b231c2" },
                { "mk", "1526160d889f5cd23902c30c31815865230ffc69c2202f8b888c2c0b98fdc8c77784941b5a57a3ca963152126ed168d799c173859f7e0fda610a26e8c73d7899" },
                { "mr", "0cf2c6401dfb6713908a529438ffe00bf0ea83e53cfb3e9a15b18b5850fedd650fe01938cb26b6a570662368d3a6a2a5ea38e39efb64bf4e2b5fe767862b9472" },
                { "ms", "c5b146718ed1fc044402b64e3be1bd98b28b31418a17a6b9a2849f5096b30804963f2b8f7fd2c0f20f27195aee7b6dfd55a98866d0ee1b22e46e145086f816b8" },
                { "my", "2a58394c24f2ae3b90e4fe63f605bc49a173b0bd7b7dec1388c3a2047b0d858045cac39c06c4603c5b7235de65d0c26551582600de691b259e1ec1f160d34d47" },
                { "nb-NO", "5101d3c209edf9df5e4925579beca487deed2696a68a25612d6f16367cd9d32a3838ae4bb937833fba6100fe5293973f7fc91a26546a73556c2a53be8691d8cf" },
                { "ne-NP", "8a1c696548d5d03b54689b35e1f61b98530292d03258c93a06454d6f2097dd68c7bceff4683a8cb12228fafe6b79f4fd89a09246a75b5e5a6d66bd6d957c3af1" },
                { "nl", "a177f6424881ca0e76ce411cc6236a1a4b46cd562f6a3cc3ee83be6974dd6e3aac0bfacf4a94ca51337fd6517b5f7227aaf33ad68bb7f1c1d0e42a98f4ae75b9" },
                { "nn-NO", "8bef1f0ecf26b9f8c1a3f9554432c2b5c379dda10d25f93ba436df5059b806959d50d519ac5be8b5b9a9690667f1946dbba9f2d2283bb2d18af0c5589c60d142" },
                { "oc", "a1ea665c7132790d109eb155c2925465a5638b6fc7b10133b06ed44439181a8425e6024cbe3c647c2c54de061d1f47decd1510879af41e22f4a3030a60812714" },
                { "pa-IN", "bcf883a2848058d194155c68a17c4cc8c44c7899816921a1d226951d716cdf37593fdb5831225de1e5f9f191bfc0547a3754ca6e6c37a4f36b3245a73b5acfd5" },
                { "pl", "fa46f5fdb60c7d426f78c39422e0352eb5ba1f34d4ccb2111cf2384fea1490151443495064e5097a880d7b5355183e355f3345ccb67eaec704286592c745d013" },
                { "pt-BR", "ef26623cb87aed720583ae463e4b528961e1703f0c91c11f0d518653d55e0b5d34284d79eb26a1f107c8a9f9c305633cfc7152cea67eb00e6263761d0b261891" },
                { "pt-PT", "c8c33e3e4af68fe49dc4335275fa37f00a559b481de0416bef955bf710ad08db964eedc19748d5b21d35744044b6435845e55ff76c36b1768ab7d46381fa12e3" },
                { "rm", "0150d4b6fa105f3ff86552cfd99e53384ad9a8f1a4a53816d0c2a932e7a2ca5aa90de2c932d038e5cfa5538c2744d59f03b0235df1c4c41a5f35b08dd36970ed" },
                { "ro", "c5a505daaa9fd28aad58d58dd9743a6e1acad8ecbaa32b10acce5b5d1da47b9525cab8b835a734cacce3eb500dec107d455d4145387bb8d0e930c18159c43da2" },
                { "ru", "567ee32d12463ba2efba2e6ef36573e7a460cd5b1c13cb85373ce89f055279773c496b792c1cf7349be3e768f23168593aa8cd9d6d7ccadbe54b2acb7c1e6b64" },
                { "sat", "f3beec087e0c7d1d9afd5bbb2443bb49bdad092fa8ee4fc72479d7a32f3a35ccb23e405c971bfabc73b3ccc24f30ef5147c1c157c8c0a89a28e05950b23251d1" },
                { "sc", "83ed9dd962442e8bbd855b94cc4f3d98290433ea97cb6a023513a1455647a8cbea1d4fa3bc6d23605138d0935b358a73a953e8cbe645a7a07e4af1d6c5359e13" },
                { "sco", "69a9b82ecaa2c24241905995973d1c111f99b90b513bc64f0b305bd8baf16d03a6425cfd51d6e2c68b3803fd9cb6faf66206cc0a9cdb26d041df474c06324cf2" },
                { "si", "d0fde05c31efd5b2db807a0ada9b24227ba9d52dd37b6d820b979bb728103f25b0855dc2139e31c2e8a284a3e88d47a6d19def7a59401a87cc09a9c1a3d1b5bd" },
                { "sk", "98fc3d4cc99a27d55b96640449cadb3f6d62cc8512688bb2d63a6b16cb0304f34ea825b323abefab9f6b0a9417f4926f5c987cf2ae2fe34a3c9d9ed27b2e1857" },
                { "skr", "8d794cad69b69b7d0e22d601521715430c4b2f4aa34674764bbd4f4568f2f5d0b2ed5336731da70d3fe3108f00b3a0c36bf656f21d1ec1f3fdaaed9e336e6e91" },
                { "sl", "b7788f17acde77809bca45e6ccb2362785969bc9facaaaee0c01250b3c516c782654b99b26ee2c466c739952b355f974aadeb0a4561644055dac83582d5a27ee" },
                { "son", "c6442bb22aed61eebb9510a8f53fad9df0f556ac03729d1650f7fe9cc85d134425ba83927a18b8df3153a2c04c9cd75c34e758d12e2049061b5a73ba9ff9a604" },
                { "sq", "cfbc984de4e66d0f245822c06aa91b23de4dc44ae9e693a982912ab945fae48f1231cc8cc011e894679bf038d0e83ffe44a4befc7f7e4512b018be3c83c1de92" },
                { "sr", "8f835ed99514ac8770bfd34a42a1a133616466adbc78a497cdeea41e419f13a27eb937a974830a85a26ecc82362d2d7267ce635874b6f8688507a933d36172e0" },
                { "sv-SE", "2151e124830fb228ae9bc931dd28a9e8862074d1971f06618f875584a7bfd074929f2a706447f132c0d2f47e51c05846af46be15aecc5250ca80b3cae972553a" },
                { "szl", "b555911058c2b9b7e4041df72803a47c0f231c6d54cfb19fb828e2e9349bf78787267a5c9b80af8b0e048417d398f5b7b0dba92672f778f44ebd5664dbff8a1c" },
                { "ta", "78afe6da58de52831f01e4f20da232320940aac3e9f46e88e912d155d9d759977981611844d012659c87f2207a4264d9be1e8663e9746df0b77f185df57cb5ec" },
                { "te", "a042be82ad569e0898a4244f56cca9af2d7b9b621d7a0675e2e0100757346cea44b27e92a7ebc096a0e7433ae2105086502e050e2da82bc498472f8a5eb768c9" },
                { "tg", "b828bca1f3824060e90a6f876fa9ab6a987c0adc5422685e4a045495c09182dcd5d8d3a10d4b4c2e0cf44ee6bf09ed6feece2d5d330232a9c668b9978402a55e" },
                { "th", "41d25ace2187a92a9776882fec334ddba57876a397bb2c9560d6fda2472ae224c3c788dc77793547b86cc40bc50c20b61c74685ed5af0cc4cb25388539d76b9e" },
                { "tl", "abe362fd9cd2ddb923c1bae2860aa8b8ba43ac9a6357fd7408d049909426f1f198c6f3f23370d91ca914d6c7aed4b4551094833027042e0c7059f7f2862cf9e8" },
                { "tr", "9ff3d79b32a79ccf2e5254208636cd9ef89f50863503536686a2b1f8a1135f09b3287b4b9e9d655a85f7acacf8175e7c02389c3b1f51b85411c9432f71c0748e" },
                { "trs", "b21804013c803a5654148768a6f83f5c4c354c6f9a450945a34968dddaf74265e5ced3511984a481d13258284ea7c3f61aa8be02f7756777a57c476494cf5b2e" },
                { "uk", "f1cf5500e48ca26a8be9868ac44c027cae9d217947e266c6c8285e4301cc71573f895d60730a45db9828b262f1c658c31240e8142a08d6230455ccc1874fed1e" },
                { "ur", "084cd305ed8a664ecc06131a2fe29a7251cedfcd9f3b5c7a3605ad42114ffe29b1925c90eb27416a29f25229d47867ac31853729220407b63b621487af971cb0" },
                { "uz", "7e15bc64ffa65dcdf04e1e93e242a87eaf3a7a07b740d5f97b9b13a81980fde5db3ac5cdc323894f0c4f1226247ffb7db7047c2b28e20bf2241e8a7728249ac8" },
                { "vi", "de9f947aafa40c03172b19ea85166ee25bf6dc3fa63bd571c9fa830512acc329f63262a9544cba6cc4a50855ae8fc43980599e6ee173f254b94e1fdb4bbe70a4" },
                { "xh", "d10983fc9d421b54aa0a98ebcf2500244c824bf5c08b8d9807540c5487dce83c713f807894b49825f32f0592c74fdde5d9078c833f9da9b5218ca24aed0e7974" },
                { "zh-CN", "eec645e2baf65d3fccc5fe2f72e475c1e59c3cc738962a8b4fc93f7d8982e775a72178e34fba19940b2e9caf8e1722fcf2fe158c8faa44ad6d4f5586c7e7f92a" },
                { "zh-TW", "c7c2273d1c2cc34eec674751644a20acebe20ecf33f3edcb9995bf181cf8e03a81e4d2fc66a3d30f4d98137eeea59453b5088337bd506e227e8688b12e1c4ecb" }
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
