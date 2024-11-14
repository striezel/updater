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
        private const string currentVersion = "133.0b8";


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
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "57548b44a1414245d706ee755efe539c9f1975c1247603b71579743c5dc5f9320272241f6efa78a41765ae6d9c36294be392c8c4e623fae8f178930a01560b18" },
                { "af", "a679f2d6f24dea7f50f7f5f3722e4eded3e3ccb1c83736fe5ceb13417548887c77858d3cff3c2325c76a381b03b9c03c5c7fe9f301f1f37862dac78d08c9e54b" },
                { "an", "588d49c4b625059c18ad057781e4065da16ed7b04b22f5442461c3ad90eeae37ab52eaa96fe6bc9e1d226350d40d7defe7cc7f01b88b3e106ec181651cf57904" },
                { "ar", "ad553190f03088b88a163f65b8f3b427baaf4ff3249f45f7a8a1f71e1bbf6b2054bcc1ed6f92f9a08e2e556caa27105b2e6eab0afd2428a6ea1a13f70466c8d9" },
                { "ast", "5b88fc8de563365bc39d526a66e8792e3adf9100c369972021ea141387485076d966a380ccaf27139257776f347d045e9cc3141a4125edfb0b0b7d26951c5fc4" },
                { "az", "e8f04b627fac728103c5aa83934398b7a78e6585888a890b2640be03cf4e3b9e985eebf0826afa4a14a9794b3631826daa1da9b8d53e74a7b91a45a45b75d488" },
                { "be", "0261693d45b11962e14c8c225d5280dcac69d595d061a18fb567fe0c533c132464c400c5aeca49d7243b41407bca0b7db9670cd70c13be6a644ad221770c8651" },
                { "bg", "6ce92db8357a10ad609c6f3a714be6af0c4aa838b1f06a29f6d0f72969507805affcec9ade1c0e5865160d07fa4ba9d90a78ae6c9f31d52541f12d283539d5a1" },
                { "bn", "8a46a32f33a3e9d86029542e0c741d8cef37b3227194ebde42435077151bcd330ec26878c4858d2049334a6130c43e372faa759bdbf104bc3623ad942ca4d022" },
                { "br", "6868d7e1c645f9eabf8236c34a425b76b211cc18fc106576acd752dd2dfc3f4c56e721cc781a137a86dcc6dd5a277cdb5a4aee1b81dd142b05134ad3a3e241c0" },
                { "bs", "ec7df8cf424b351f78104f57c9143076673d2f070a08c536f00a54f468918574cad70c344f30282bcd652067fad68b1da72dc096e5004b22ea1e1fb8470b8c56" },
                { "ca", "08ab62dfa7b68f56c2585530b663f64919bd290557f92c9d04767fd01c92805333667c1e2b22991dc04de2bd132bb1c8d5b382a795ed5a57023a79a1686875cc" },
                { "cak", "a9b1714ef479e41cba933dc22f9688dae0fe091179ca29c5feeb02268e593680368f5be08bae58f086771b1dc190437627f8ec09b0f10043e6cf1aba05ae0ba8" },
                { "cs", "2e5aa4837c5a75f8056e33ddec9b758bd8ade44fdbad58384a67093b3ff022a05d308dc542ba58d62bf35c8ec2ca6f57985924e005d34fd617f8aee960706f2f" },
                { "cy", "7bff18148c80ae759b31533468f356044c80afb7699893b47773c65999835b90ccd7280a86d22601710871f1c2f9c00f8287c0b277ea01680e74019a0c25c742" },
                { "da", "07bd192a0497955184694e09671cd1b7311ff8ff839c983b6615aaf0b6c6a2863682cd620c3a07510db78ec14facd5a1b382f354a88c09429255e973ab853e9a" },
                { "de", "989ab26b0f1969ab77662ec2f286021f2a06a8c3769ed590b3e28a46fb095e5e918cd199c1a66dcea34f02db578b1cd407b33b8f726ffda6cac7bf6a2ef92059" },
                { "dsb", "bf0c8db9bc9708f7281b667d93cf90d5d7260024d3a0a185f14baa135f511f9184e56845d65b41e6d7ba3666dbbe7df36759a844d7ded7a0b90b40beb71f8115" },
                { "el", "2fc1646a60f3c2b53aad73280cd1cf10d66bb3c1e3e11ecdf224ea2a7f638763725449a89924733847ab946eadd7fd0191c5a6a8a2fb62bdb52b8494359cd4e6" },
                { "en-CA", "580e0eb280a4ae470fa2b510098ab6cde04c692ecf1042d45723640d8152cb5e064fa5c102b56dc9370a563faf345db8084d7bbb03a12b67c33fe937e4f12080" },
                { "en-GB", "c57e9500b2b447c2da9dd9dd7830e17d80d7fbf3c63043e37a02d6a05bbf0f537cb2fed55891fc0b2106e80711b01408729dbbac56d8849f2432221cf3145689" },
                { "en-US", "ee4566d17a586939cf566e85d60e3890a44516b7bcf4a29fd535f49399ad2c1299fefbec543e67d64ae73a706c92e27d3d1d46698b46ca1754d9b105819f6ebd" },
                { "eo", "a4199ee2aeb426af6488c53ba5214b9901bc2504e82db991c5a8a3e493d8d082feab1c1142f88ffe63007f4d8f6b22c77e8a7a2eed3786193f59b158c0323c35" },
                { "es-AR", "88deabb3d3808388f31f0c560c09fffbb8960194e57c31c2bd8095533b77bb198d826e3fe8cbb7ed61b13e5bc5cdf4305b1d43efcb535ea5745b540b95a470f8" },
                { "es-CL", "d8b1c647af6d517ecd21e12e378a0aea5e1784ac470d3a9aa8a56fb2c4f9879d3e4b01551cffab89e30810b873da33f3d47b6b5edf7690e1c704037f15c0890c" },
                { "es-ES", "b741345755cfb456ee6256e220d7137aaa54eae7d41a5cb2d942ab65a8aec1e9d9777458e67fba0c7c1a54dc5835e5eb6b4de8aff20ed6118fe150916964bb7f" },
                { "es-MX", "fd2a6c554e94fa6f07127fc7d2f00c9009c5d8b69252ccd1ce8b5f273ea530cf18cffc208b0f932321e2332c55fee580308cff176cdf5d276de475de72cc3493" },
                { "et", "64f543bdd17bf0b8f63e9534da07c94da39bfb0f9c645c80b79e66458156ab25f60822583a59d4e13bb71d71bcbb1da9021d186d7357139f4cc66b973e218594" },
                { "eu", "d91e9b91295882c36c5e45bb0f1c9a6c6f881116ff75c2880c51d3772c52fc2fda770d26e5c184e249469b90d86c19b3055f60344f6b7d6b4c123fec623037fd" },
                { "fa", "609e2db27839b6e4bdb3be4ae8543d32e6fa7eb1a78319fb933a7ec302e7fea6911062034034d46518b981a974142d05f2f3723968b00c840107aecfc1cab33a" },
                { "ff", "a1576077aa785184ba999c7df65dd0faa5c6171833a124751c40039c4947c9aacd1230dc33dab79da96f6b4e409978f6ae8171e8aa107535e99c81d3c09f3cee" },
                { "fi", "7d8f1043c2cf2c6e1e8b3f1e2b0beeb6cafe6e5ade870ea5b37b01296002db4d560ae2bdd3949363623659b9394e292834f40d3b7c045600545281d8f2b4c5c0" },
                { "fr", "9a9a45846183ea722b1f1d1d6d2f8083c504bcb3178080472ffabcdc8110700734f345285afd1cf1ad2c1d37ff32543b8c994a6b7fb707260817ac5eaa114f25" },
                { "fur", "f2c54733d7aa9905136219bf55f17d5b9a6aa9cd3814357a3f9309b820c7a9aa3d19105b84b798a819a1dc8ee751cefce9e78ee29fa29ee5a16dcaf5b24562ea" },
                { "fy-NL", "3f2db8cc5c3d22a2983618d5356cc4959b847f531b0379146de6ebd896f16d2e2cac22ca8145a1a64709fa6baef9a0dcfd14f929f34f9bea6e898ff2d1ad1bc4" },
                { "ga-IE", "305200b9008294b9244548311d69bcb5fc334965235dce1e814124d4ece9ca56b115cc369228f26b54ab4de068085d4bf3ad1841ccb59d20fa41ed9fc321a73b" },
                { "gd", "ac3ec50c764f9479c8826bd0c52569308fdeec8c87b3ef0f05d214f8a89f019971b8c3a915d2bedcc3f381ba58bf544a11a651cdfcea9f9f5f6a5e7109a8f90f" },
                { "gl", "50e07fe8353d8ba124f4d1da1001f6cba27ba97efc9896c2adfe2acc1fc2400f3df89bf235eea3e062ce1d8942fad14d0d9a41d8f1a67372a8ce0c68f795fbae" },
                { "gn", "2506acef6af493dd776c4683bd68abae48437dc2c98023dbe7ca87bf81e1f99b0964d589e83c0781815490eff962e4e6442e7b36cf369d2c223a1c2e10cb0483" },
                { "gu-IN", "74d729324b7bae2ec805c704e070b4c1c782ade9b7e8e1330878e6827bf31b7078b7581065394bbc4b63342e19e31fec9613d1675e42470c5d09b08d7f1e2947" },
                { "he", "739782a8bfa90d2aea5fc5139e43b6aef873607721b375c73ee24f3a3959c204a3df7a163b5a0c736b0db5f38e3ed5412a996f4f7e909d407adaa986cbdba689" },
                { "hi-IN", "9a46fdc0d2dac95b8057d84c8c79bfc234de77dcb17641f442902501004b57c7ecbe19659e560d5386b148a8ab2ec7057fdb30255a390ac03038b1c57c14e894" },
                { "hr", "c1e66adfd484f9891869526634b41e03475de9ae74beee4e2182146e0a77f4c4073ad24b8073388dbaa01017923fda079c2f5079ebefe4e0e2d2f08b332e6ebf" },
                { "hsb", "a01316cec8f8025be472ed7809d39e7276c2db0d4db7cb6f41b1c33192d66d97dfb3455abc82ae1d5928bbecf17b095b729a4c48db7bf3fd60f28d2d9b452780" },
                { "hu", "01b2dafa02d660598ee5d279b459950a607976008219f803824488e0f2832ab94d7ac272bfa5d5875276b619e1373c4480d1732eaa4682a1094dcd4b2812396d" },
                { "hy-AM", "e9147568c6988e21c27472c5b25448c0bed4e2ccf0dcd2a6a2300d680b57a85ec846566c6a5d86b23d0cf3d3519c2e5e21651b91cdf0320061e1c2af4c8cb630" },
                { "ia", "3019d909993abe6a8666a14f8ee0dfde685562d1ac1ec34d2932a0377d030013e2910e7b09955efed525af04fd7dcb62d04bf93638bc9d3d0bbe9e74f0063755" },
                { "id", "408ba06273970231af0989deb87ee4e724a463d3806790d92d699d7690f569f78b04fb07a2e72ed169ce025e9da16112c7c740f091a639483b9927728c0a7478" },
                { "is", "2daef5fa1f9db0037b02c829870f43b6c6df84a5c367731d92257605a998e428fe6216dbe78bcac93e569f98fdff14faf8b3b85c76db65a39d717f0d776e1171" },
                { "it", "c0e3c2caf589a41af3a463602f33e1d77b42376b163d2440fee494baf80fce9656b18f417b284ae58b8ace6c20ebb0df8c65415e5ac2051c60a433e741e5a427" },
                { "ja", "4ba693c6882a155402f9b08c99d5ab54592995c6cf19b017cd99d10af14b7980033e89da7dbdd6c55686d428164130ed573ffdee4f8ad07a6436b438cf562b89" },
                { "ka", "eff459876f2ec6124e95f63970715b4bd65c15a3fb4488e23c28f59f2ed2589c4b4632c91a97c879001a54236ca26cfb196be55aae98413ac86d8e8dbe3fd1f8" },
                { "kab", "2547706ce554630f75287ed0921791501012392e996ea43e3f3b1daa6160605fa97710944e83899825dbcf5686550cd007ad6aa8e97db6138fcd3a8eeeb25383" },
                { "kk", "a60fda830540136786ced5c9c262ed88acad02f3ebc77822e9f5dcce3506b83e862ec26c9c0302d19abeb599bac5f5e49f3149562457be049f80b21b00176414" },
                { "km", "999a9dc42ef04ddd967b5dcfdd5d719caf469cbaf6d272f85e8406a5c3d0fcc482719bab082379cca0292f90ba47bf7f339298a2464cf9713888e4a2324ae6fe" },
                { "kn", "16ff42c05af8e3797ca637c98f985a8efcfcccdecc539037b2ef1a0df8341597929faaf53ae8fc047f673d631b4d69d7fe8cfb74b1735e77eeadd24390653698" },
                { "ko", "ef12004d5c13ae843bf3db51978a6b3dbf805660487266bfcefa20971956d2169c428fea847ee04567c1556f4717ffec8540e81962c4fcc2ea079fd000d9d6fa" },
                { "lij", "de238b83ee72cc0590be76be93e0d06af84385b2f65f35ac7cc9bffe29edf75c4042be751c88c4f9a7cf15739ecfc13af90efef3127bbbd5ab234e56ce069da3" },
                { "lt", "cc5ff452561f02879e1ee0dbec577b64e01d1026a48d4381e1fac536187c35dadbb1b89bb32310bf363399e3ff8dc447f5750fc17158895ed265d33cd580d30e" },
                { "lv", "fe556b5b33314470706f2fae784f5b1d20122667813b1a3c3eb9621b02abcbf8c7b2226af4534067db60eff6e1955898cc6e48319c47e16650b2fb8fc93cc220" },
                { "mk", "bf639f7fe40ff8d1ffc4d62dc99ceb5e319a31d8c9099eae4ee823dee29981370ec6c460f9f8c9e0fceed443ea687bec7db42c938e20328d651a23b1da96dce3" },
                { "mr", "0714511267ba4c917f922f0d82f8b41ecd8b213e33cd7cce759a876116df28117b04fef040585a88eca76a2b74574cc9f8e4e8c69dbc371f56c4da75bc9f3e86" },
                { "ms", "eaac53f27a5705118fbbe83ea38b2182d75c124aa88e3fc77260500b77c23499e91f2153e03fe463679ab020d9e3620b31322fb91f6d35f5c7ffadbc3b478a2b" },
                { "my", "321d38428172942d618f25557e742e0fbc390b5d64d70e447c434cb6c2b77ba251b9ec901a2da21b8e05072ea36e942dd56df918de051c4974c8c3cef48e4f21" },
                { "nb-NO", "f6b4ba0015efcdaf926fa26f78817472e3d7126f2d78bb8364733b86f0b713deddf51b764fb3e07df3cee0a45f8be8e0016493cfd2fbd112ade4e1ff6f3e831a" },
                { "ne-NP", "23146bb7d1bc44e9e1b3afa80c8e53ad5846e75d2a826cecfdfd63a25c7225b3ea6f1bc17185edee10ec241dcb4ea80721b8d0ab6ec1fd00b81a73d3b0d18712" },
                { "nl", "5cc30ab49af6591334c1039faac05fc31b9b243ae908a4f044d36cf8e691aeac45965379fb26ab4ebc1ffe472eadc23b55cac69fe13867b8fc7ba5ddc6470406" },
                { "nn-NO", "083e8d0d9626fa3a38805c1afc206b9109d2ae912688099a1884a46f02057563ec303086e09d1676f3a93b70934a271de687e7d57e5e598d3e5ad518ae89c8f3" },
                { "oc", "dc2741b6ef6324232f5ccc499da27185191d64f74550718e4d94bf59453f4c18192a42681763ff516d2a5dec61bc84ece52b13bade377b411a179247912d56a5" },
                { "pa-IN", "7883b228e95ac1a08fe54597fa40f8ddef3673d882d2d6c8423c541e1f87303c6e7d1cbc5b28a33491967676218f0e7c09e2cc0f2aea08041e12fc703f347997" },
                { "pl", "3343611d63b265af4191ff769dd7dd8c514af657d061ad07d77dc8e6ae5e5975c049096c3d72ad3fb6bb1251deb7a2e6e693836c0692db832ecb984f25e93b80" },
                { "pt-BR", "2e982899151b8d0e94299cf86ff9743874b77ef413a4e14cd5092bc6a88d1d53ab99b1f84a45a327e0244cb9c951740c5687d8df6a38eb27d0405f51231089c9" },
                { "pt-PT", "06f80975cdd89450438a6b975affde815544d2699bf80f2138fab2e9d2b15714e1ba243be02ea8c0219c10fff13894273d8b2e1c7549c2a0a3f63a86569eb114" },
                { "rm", "1948ed4152e5b18b25debedc261f2c49366282c2f0ad4334d0434a05825bb01991f1d041e5fe85aa02616a516d635eb2e6dd513bf1deaa5d6664785ebc282383" },
                { "ro", "0f75edda3b7dc233c96b8bd42c605ecb9f01efe8b7d1a5544be305797774113d9126150646a5662d25b81edfd73c9da7fa542d69cd65a52e49c09c4d26bae9e1" },
                { "ru", "a4fe55713bfc5c43a8cd8a507c0e888ef37560b59449dbba5a320d5910328af997b086dd3413855462ee34e771d1822879d58bed699512cf6f033ecf479d374c" },
                { "sat", "5a17f5355c2aaa16ce8f2aafb6ec497ea85a2ebfcd1c622698ac23cbec9138fec89c20d89704243be95bc2da2a2d660ebb56edc7366d4bb039bfe5710e14b24f" },
                { "sc", "0d134092b3184975803618811774d345d90149be27c5d8ad987227994ee9ae6a693be8e8785fe06ef47f07a2af1e8251566430d308c2250ad70b065cfac0c0e4" },
                { "sco", "adf3ce132a0d3d72c0a48439e93d80acda6ce594fb8422f0acadf592ca68c5f3f8be10741ad2a03ebdd108df84f0c235d051bac43cdbe226a97ff71a346663a6" },
                { "si", "4e184e5adedb743348360408f8f35cdef4036d73fbb642bcae5eb555654042afeab47a8458ec99c3738da06136b00061dc900ce212fafbf7952a5a8ce1a26d02" },
                { "sk", "9f2a9ddc6235c2176516b6536ce592f9636bba6e2dbbcacb7cb64854374eda6b18d1d622e3717b5cce23d588673dac366c2a351ca95aba427ce6bdb2baa58476" },
                { "skr", "182cff1c3706c754c6d6e1efea6dd15b6d1f5ec487306ae00db22c2cc47ca8d7150b0223702ccf175aa324bc8484a09048706c0003adba6d773cf5d27c0e0055" },
                { "sl", "12d0908f342880264c25eaa4912e47a4dbcce53099aad09bff9dadfbb2336946a5ca88dfd6a5ea616d56019de5d4bac030e96e5a88f32ad04e41a7990182c1c9" },
                { "son", "812067705e1297fb09d5041989a5a30b0aca4378f33cb04ff433f40ad76881b5ad7b44931357139969e081a635f69a18697cdb23f3a280d3475c1bbc48ea1325" },
                { "sq", "cdebfc2bdb4dd93d59ba4a261eb9cb3e8d7251404ba1f0f6b02b2e1c9a9e87779d1f5a039bc5342ec194374096fc17985efb49b43d75551c01d124dcb3a311cb" },
                { "sr", "7c980d15f41e4f2aabb8a74419b020c3711e42aae31577419f940088302168a254c7e7634dd8dadc9503b97eee5bc756fb7d2676ca905e8d45a31a1a4b2a0bb8" },
                { "sv-SE", "2cdf09602b2dec7e5e5f2945165e687f673260ebdcefa4f9ebdd1113eb3ac9f7c7bc84582f995be9b89a3692ecd46250f38d382029b2632d59b372c86120e6b3" },
                { "szl", "cba746317192aba1af1768e2e1a14cd373c6bbda54a0d56632a8578eff30a3528193534f7c880335cea4f49bcc0f4e8fc7f3971c2b0eafb4581fa6b7c085075b" },
                { "ta", "e718351c518648ef3df904e320cfefcf09bc38a5ac995215acc1228b75d590350c848dd4e018a2f8a39cfb159f44084c23bd5e9205e58cad1373c589c7ec3728" },
                { "te", "1f11fea4e8e7f2e84e2baebab49e6819d8f70da56e2482bb69b237efec885b8cb969168a2977ac8926de9adb1de56111664816c57f9343cfcbca8818a72bb7c6" },
                { "tg", "6d2ab37e7802f88aa9b5441b9676862d7f270937bc71866dfe56ec3d5796dbc6039533502ee41b09bc3507d7b65a200ba04985de51b70a17d9ed66a1f7af6dff" },
                { "th", "21a9f02fa68e472dd75f409d33dcfa59f492b2ea41f460c34f0c67072e71e862b57af3c766770d264f24d8a1636d4084ce891551fc639ff61158cc05ceae59ca" },
                { "tl", "dabd5ce8f9cd7b180d7f3c877e3e9b8c7b66f4a83feb7cb5d7806139d772d8d486cc20cf07999f434540bb20498b7362adc10003059010c54b53d4846640dceb" },
                { "tr", "b2096fea52065319c54eca00af8a4b07c820085c437ca4fdf10e3daa405de701d6a4e80720145ec3c583ce837b377a9596018db75bd4e60bc46c3047de4377a5" },
                { "trs", "dbbd969915a28cd57025c7e72f918f0ec7042ab7d3f1c882ed0c7a3fa5aa836a9f9177a33a945d54b9f2c3257b1653d68f8c7ce3f749b71495e6bbfeca2999f5" },
                { "uk", "20d5dcbfab1512385558a24227118249189b3c4a7c1011027227ec0c02d9d0edf4790df5007167b34aa667e23e5ea572d1dc1d604f901882d4b39700b14e5868" },
                { "ur", "2ff9d04f086d28c4401ff0074f4f791ae0b12307b043410af0318b164bb18e41c8bfad1107a486a7ecee55683c1eb1a595afa177e619bd7774d44772f94bbd2d" },
                { "uz", "9e3d0d217b7bfcc7a52908d300a764d08f2d9fdf2c74815e47912e315d50b3d62e492fc6d3f806a3efa000fec9e03d727bdb3a096f350f39b9c73ce0c2349d5a" },
                { "vi", "17a0b6bd3b171cd2c2d8cf85596d2efdc897cd20446b68744160656e9e875bc92cc4f969b4cb708d90162ad6976463cd76df055cb7591474e54318b562cc3977" },
                { "xh", "b574dbb4ce1df7401279517028e97627324785b5d7db84fc1134c6473ae5f5896cbb7a4609a05c9c7245c1deee72c8a9e48558344a61676377797c3b92bdf313" },
                { "zh-CN", "10a9b3b60a62a7bc997b10ad97abfc1aaf337db5f1e30e969357510972806c838f02aa6a2c76738fa5ccf2b0dff0d69f45ca8625b3d9e742d36bec519de5e51a" },
                { "zh-TW", "b5f23d534bbec8ba3c2bef8c523823abd6eb7dd59968e801ac5ab891631862195dbc5b628b116546bdd1b9be6ba7b44d497def5f05e56b1cba6fc55ce6d7b403" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/133.0b8/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "fb8b45708a87fb5728b8e7d52bc318ea232887d12f6fbd549dc49d2638c2548ea0b202a5b58ce0b34276742bb5a96d561352eb840ef7aec8558d314b0e3d67a5" },
                { "af", "eb89008cc98f571772a4d57f993125396e2e317b8fd8d8f8f9aa6943428d82c29c418589e2581609d775f0fcc48bad0b7a767bd542faf40e795a9a4abe41f065" },
                { "an", "e4dae5b75b819a26848623d98e4da4579ecd103d9e71c93e27c16af584301ac96cddf618cb73dbfb5db53e753b48933d85f5aba49c6550448f5f8d40102999b9" },
                { "ar", "9b1a5c4347a244e2b45119a948ea3e0b5637fbdfff788b230b84ce488ed1fcfd1b4f32ecd166e456e68224a07f15ec4d99ca59a787a60ffd9a82aa974e96d677" },
                { "ast", "75b59edfdefc7d07ca790af19a52ea226c82851d0d0f6b7590ff1e5b82b21010d2408e33a0547d868ccc6aa3472129425f22e8f2ffb351a47f64a0516df03103" },
                { "az", "8a71b1c3f1e9d911c7e78cd11dea9b11be9ed32bea3b7076d4592dbad95a6875cfd1ca8f235d8e25c2c4325105b6755de386e94ba5fdacc6ab803e112c2378ff" },
                { "be", "e5edd146fa9fc001911e261883f6968cd679c0aac2f803b339ef019bc4c59fc393a8c484fad0d8e1193c3ca97d21027eae3f42652c03b565d1ddbcc2a182da49" },
                { "bg", "e2e3fd364c14c59efd91691a45b2152d47f3160a988f5159d3b5e86adab090e1eea748619fa761cf1927ee22d967702eb1c3b8eaf5e520c9b1b44ff1387ed911" },
                { "bn", "79fdd38423bad7ab86c94b1b8996eb810b5ad2f94686deca00fa9bbe26f71d978a68695d2d5582f3a76c3281f1945d70c1539a1bc704668148a4d59a9717478f" },
                { "br", "1e55874a48f0dad16b02bc16a14d27eb7ea5c5ac7444cc967bc3a5ba7deaccdc30ce532e9ebf0a8b9912db344f2d980db4b8f82107e2a3456d9388efbc81d7e0" },
                { "bs", "58e68146fe0975eb4aae1dfb485e3e7d06ae4db23085cbc82d1221952082d3ac647576029dfa0dd6fcad86e121cdac1d8d16c946879760fce9c63efa844a166a" },
                { "ca", "6f2c8cc2b54a6d78b0f77cd23fe210fd3d577bc42dd78e8214bb5f044b74230aa936c354cb823294e1f06bc75ed234979a513ec3dfb41f575509a710747fe785" },
                { "cak", "1758dd3e3a020c5e6ffeb6d37e712427ad937c25d60e4253aae1d153c97171cc682b5baae4629ebfa2d132f1e53948c62faf2cf0f3261ed3aae63679e9b717e7" },
                { "cs", "0007c9e6e823a797904d6392f125b59c18a4d52296ddf9f5aabdb65ca63341defd5f763c3569652ae5795c4edb367b35281d543a4df7921871c4e9807c09067c" },
                { "cy", "1c6783049f860b6f83c39ff4e15589d8c8473cfdd1a8e62cfbe0b4810da7c30ebe32a2e6134e612fb2c7e104f5a845b1fd05486b596f3efc748be2c76ecefa86" },
                { "da", "f21dfe21febe0ef64011bbb54a92a3f5b6ad76bba13724308998b356f2ea68c49c613025f1e4fa547a254fad8c2adc719db70e03eaea75187a4aa1cfb7310865" },
                { "de", "bcc41c06eed7399034d22666922404f0bef901043e65cb508d2bbeeab23bc84518a2e7a884f1d89cdb140d5a201f635b0eee3bb9d8247d076bea5165eab350f5" },
                { "dsb", "3a20e9dee0785f147e93cf127a7d1fcd27f0d22dcbadccd56f26a4f3e356a8df969886d7b54ee5f5807267dce469387282ed50a3a049f4962ddb4f0602f4e6d5" },
                { "el", "e13fdc3abe6ae520935627cedde2b9539343954be48c3486e685a2c016cf8bf18817296674149698a443b1f8f41d0753e2679b0c0cc39336d5361bfc22369e3d" },
                { "en-CA", "4a13380a17c8d7c132675efe6adb0383bf8dc72c09d0e524a73140b2e09952a37fed52bc632b4d53d098c2ea6f300fe05cdc7cea4d774c1dd56e11cd353372a2" },
                { "en-GB", "0a2487a79dc97ec5b5db60fda93516ed0529b5f272543592f4cf9ce00c4697951cd16ab36480e6bf0a59e07977e963d894ec4c9b49dbb73760319db7c283cca9" },
                { "en-US", "8c3d18518c60bffcbee1047bc124b8fd3cd9fe1627cd3be08a57f15cc8755583e01a10f61a7778eae6dd3fedad4037eb1fd5099e397cbd7c847dcf9bada2bda1" },
                { "eo", "8365779652566a1cc1507805c6f4935aeba61811a15d3627814759610a46088dfecc3076c2d3a798988a97e51ce092629aeac381a3d66c145bc5e686a7d11c42" },
                { "es-AR", "85b1ba13d898b9b1ba4b1d3d8757cb4f65746624127c57ba074f0b9ca11375d9eae96e411593c4a5d9e1ec7acc813df8a9d9dea1fd65d616fd2bbd56c0a32491" },
                { "es-CL", "229465c6689355877b6f531b00971e3cad06b52a2f303c272b14ac1b578cce52000c21f0447ce01e42de636f1fd5c8df2b64c4bb5da8adfd3a580956df559fda" },
                { "es-ES", "f8e077819980413e6eae24bd4689f558372da4f264574fec528a73f28c915a9aae642a2eb482c87a7dd88c7d618b949174f352e0a523556c8125f552e8c233b7" },
                { "es-MX", "0a24df89e691b8081643ac66768244566140c1d4edaf84b2e8653d6adbe6f1a517973c17d76a2938ed5e0247a2114b4d81efd9bd24cdb2b160ebb13497fc4a9d" },
                { "et", "c5e83e72a540df7b2f92d0880d997be1f1985926fb0fa487f92dcdae507833ca6ffb9e79dfa93950fd28b57530630d04e20d7c485f6165982410f48e51fc0480" },
                { "eu", "93a7d83b5f3c32f54f62cc39d9af853f2f0a4d9a0d675713c4cb54ea3bd3d418bb961da166d16231f2aae160fa6489c74c71e0bcb8314bf5dfba4c0afd4cf5a5" },
                { "fa", "d86b69bb28ad7b16162d743bf2e2bd3f08b23e8aff7a4da47e45a7e70d5320690dbb0f1fff00572903030b132409114c95f52361d691ae56363c7aca979880a0" },
                { "ff", "ea101ccc15a1dd3c7055625a37972831b761694f9fbca953fb7c1e1321099d91de461c725ce1dc11ca1f6302f10409891e6fa8b1acfe8b0cc860cdfd43d40bb2" },
                { "fi", "2586b4a64c3eafb0255a2a8a2a2438dfe3e2095a787ddcd1a82d4dcb74278f394c88f53d4950dba0f0379a0956755c8fd07b95a05e780a2b773dbe83404db198" },
                { "fr", "81aa0fea3562b14805a12b7fc0a3af9f889394b3fa629bdf988539e62e8d6fe26a1299e41b9dcab0b301ea96a4724ebbabaac710206ec1833e979b58d60efa65" },
                { "fur", "4c3871933c85b3bb8c1ccc4a2cbe4f3284239b6a2cfb5f401a2741e512d4e7ec5e7bac5bbef3ab92ddc732040854b412448e929099bbee5f891a213d4c03af58" },
                { "fy-NL", "3daf854a999c16f4497c68be91737c4f2a0594560d7da915073de0274966f77f64cdc0d875b1b1a95d4f9937d9238e54214eec980c6f3e54ef26f8b2a29a701f" },
                { "ga-IE", "2d670b70ebbbc8c70a59afb005a26a0bcc5c4715f7e00bf8bdaf02924e1ccb3369fedd026e4625aeec47e536d5179cb2d6c1e552512aa43633de3d1c7c1d3a8a" },
                { "gd", "4a99c51d30afb07bbd646a055ca2a4e0a2b01828bac71efc643b70648d298468fda7e0ef5628b6db81475c4a756017aadf5cc9838a8269cdcda24c3ed626005b" },
                { "gl", "a8100ba1ff6868e4fce538773511b5144c470432a64cb7e2b353c74ef4048850e865b7e0ad486b9dbe4b73ef427aeb7c43de7ef2047bba2abab549c4de58ffee" },
                { "gn", "84cc534b069b8cd2845d660f0b240d82db7bc57d5929b9761947de336c6460402169a63d9f9aeb110aa751093bf70f06d475d87853e1ea7b9aa2c07f8124e46b" },
                { "gu-IN", "aafd6a7b8f502fdd599b6af44338580f83a757765915a9f44444ad52737b837fb5e95ebaebed485009c2f828946be8c2b610933bd3d0a836042975366e5d872f" },
                { "he", "23b1340a3a39393791a5e70309031b3cde16580aa29efccf770ca6b8323948da868195d743cad33328040085749a048ddbd15bb5e3f0987ff87c2ee04e9b320b" },
                { "hi-IN", "ef0c1c5aa3eb8986feb4c71308a166a1e46cbf75f60261e82759e46bed5e08dd1f17fd6d1b4008dbe6c88985555186ba50469e4aa4d1ba683f3a35ada1680912" },
                { "hr", "15dbadf69bb7713ad19f743206ade7c3fbc329ea058270a83cdca402cbce465eb8bfcb995f3871295607793a6c9456e13a7902bfb6ae73897ca701be5b7bd678" },
                { "hsb", "db985c5654fe8e4de8abf15bee0ac82976c4524f5ee738ccc95d002acde29e91c81272fe05387d3048990a930747f0d9fd2b38f6ebc8110070f344fdb4135c72" },
                { "hu", "aff3e3befb038bb47556402758a4d3fc3b28ab0187b2cf08f28a7a1495d90001ba3d46a6097e23ab28fbdd414310d1985f46c03e0d78b2961a09c871a30d8852" },
                { "hy-AM", "e92fcfba3e52e008189e9e8a527985da164785ae83e1fbc377aac198558754490de31fce12439fc1d334c71a0376228434727e56436bab8f2c8f02b37b135ca8" },
                { "ia", "4dcfc47e3d6e8b3c4becb5492acf65e4e035740e974a1b7aafe14c57bd258b476ffb0631a0c481b7c1a06bbefc90d1f1718920014c33b63ece6b2d066f5de1d2" },
                { "id", "9626f559f9a39dd9c5e7a95961046b351dffc974533faeb76923653fc7b3bf6d9e065e26d3b8490e3f00d10b8ab98b525c8ced7c89a908228587e9cbc64eca46" },
                { "is", "fa4d9346eb600197b3cf1f27c801b155bfba39d1087e5e0d855aac9b39f78b329a0f46f4a53b8ba39eef2f551e523df6577e0d1efa65d29022f6d1524de32fb2" },
                { "it", "917a8b79cd87786b217325b8d9efe8335bd2177fcd072a0bba82ec850054732bef91bdb2bf68c2706fecc895dd370310836bb7187816b207f77845baaeb715ad" },
                { "ja", "51d17a7e22236e8895db52beedb70ed40c0937f36129415e7c976a29842cda42567516b127763f39481d9bf2d2a7dc3f8a963f2c28fdba959e27b12ef5d7f1df" },
                { "ka", "6904b2a92929d7f1231e9df09e8d2aa700a95cbd1ba47ee72a76d0ab8e280d5b0ccf96bb1a1894e5668ce6a0371688efe76065d9112b30627bf3322559e22757" },
                { "kab", "5ae7d34b4b11d295720e95cd5e647459a8bf2f9c1c1e5ada5cf453b0864666cb7a7e4d12e542c2465943f5f0a71252be02b430437a61e33ee684c57a464f8738" },
                { "kk", "8560cbd6f6c98ad3c160166abb02eaacefea5ce7002d4de46ea97298867818adab4630dbeb08478430a28b3788603d03122b19ed3d86b8b5d19992e42038d3fe" },
                { "km", "63be298a2a046533c79b1635ac1bc3b9535dbb1102ee43c377056e165cdc3f8ffc46e42a8aa45e9d3cdf2f3092670f5aa8a2f9f2707e2a11756c9faf8879ad22" },
                { "kn", "58b56df5d816f9d6022a91515c440aefe5204be9285833029055c5a5afb61fa6562027cae15ea1162649e8dfc18f7b49e08a2a43cc1e1e927cffdc9267075dcc" },
                { "ko", "b21d0e48ece367b5091ac972fa8eec264e8a1d961a3372806130009c4486ed26f0b4c06e088c5cbf4b1ec5d4e41440f60be4ced41ef72eec40a06f1624c18f0c" },
                { "lij", "ba63d370c80f8be6814da1536800470d05a3247cc116cf87779b18d3afc08cb14e96b10269ed361ba13296b17314b06508f7785f251c4c857408773dab6d6989" },
                { "lt", "357c71b3e6c1de216d5dd186f510a297d71f5a83943ad8e7e81a73eab42505d620ee9988a92154b1916f4d347472d9a6e2e3ce1c2ff2586283af3f626b220328" },
                { "lv", "5a232fb9b8e86d26813eed85b543b239e7ef9231aeb7fee87811abf8e8c40a6bd3de100f11241d6a2154a897f1e5248f094b57ef842b488f6efff8ee7aab95ad" },
                { "mk", "fadee6b6fcb330edfff649b247ff0ff7fffbc303a674f7c911f2c3e04b41600f1246cb2645118c28164391b3dfc48942f6b4cb137538dd8d1ee485c99eb88124" },
                { "mr", "e19236517e60cbe71efb2c8fd12c46cd0a3e0b8d5a036a6da5a08d663f9fe4f957c04aed9e28d418ad1fa8a531ca70381f8e3b04463a5816985126082544ba78" },
                { "ms", "a056737cb4e73c8719c30bccb6ee201912f29710f472b1df63196e9b0e5ff0fd089093356b8b0dd34f804bfd5ff50275236934a4bc5973d16259254fd75356e7" },
                { "my", "110c973c816cbea3556029b8f0de044ada9946645c7e0f011aa6f8664c63d599577229804c2c83f61c7b1c66cb5be28780f599af2aa705f41f514e88eaafe2f3" },
                { "nb-NO", "101dca51266860a826a7e7687325ac0c7032f5e8c32a53e6640654cef0eca7426a566d683d1ba827ba90bb3716b49144aa498fe6d397bf49d39b9892ae4fea49" },
                { "ne-NP", "ffb2d1c1d78d6b56b0b3aa50cda5b9da6e0152e65fe05388a60c7754295b8a1aac662189876dbf9946f6645c95bbaa31f704b09065485a0bd5ea328972dd4177" },
                { "nl", "4806ee66b23c39926af552d63b2dd4fccbe06b897cd15db724128ec1cb3f14b7436ccfc15b450c4b5326959000cda212f9998a3094da73f245acbd6aadd8235f" },
                { "nn-NO", "7098a34b0294f4f2c8e54c245cfee4d3068bfc7a5bd060ac40843532047c7ebef2f1e5f07daddea33d153f805dea0e5b75d7df2c9b0304b6a87f235629189fa7" },
                { "oc", "22fae810bc2f7f4c30f7a5e321977a7722b8bbd48196399a45206e354b268149bf7c7f576d46055af0df5e0da924b2d0484115dd845a0eb8c02ada0693ae1d24" },
                { "pa-IN", "5cbc345691dc788f52c337c059c21b453049a483dd687fd72e66390666e67a933389039671e41b133b5d7a4c53c4d8ac38ed911b4e8d4b68ec8b563ae0a44033" },
                { "pl", "40c897167976df7a2ae69f9cf55ae545b0811c64ed2bc8063e91cc8c2feaaff11353c28e05bbdd285369f73a066eaee8d4fb9a398a82828229c32f43e37c201b" },
                { "pt-BR", "e1e0c5ac68fdc7195f367481e5d42f4c184a46fc915f5feeba7a0b682e3ecc93e402ef0093a50ba19bd4c63014e1b7ae80dd86ec0b0a91f4727bcc69643c6912" },
                { "pt-PT", "5da90da9df14eb7e1b0af81c95c65a8cfecafaafbfd417f9517a0f2bb4e08cd0c3b742f0ef8f18374907e8363de69b81dd9e20470844cad2ef94356fa4384b51" },
                { "rm", "f286adc9e709833733e88316568b9fd2cb08dda63f9cf984b12c6b703c75c1a28358d422b291a119c6b48cfbeddc144249c7b58fff648c2dbdb0ed9a681aba17" },
                { "ro", "95b7838bf7fde79200a1a66051ec4b74a8890e3e72fc4bf63618389aeebe16e7ce2605447a296f3f64260da38aebcb53e0d5e7eb79474dc71536aad4795cbaa5" },
                { "ru", "0499a6d694dace081c5680882ea2cb5f9ab42905678d39af61aaafc9aeb42323ccee3899074a3b27ee103949ecc1cecb3814329b84f3dff81d959c5d2a5b114a" },
                { "sat", "cd538fb1f1ff8f5419ee41bec48973b6c872995da03f62e5e8a739a0ad8b1d36ef8e5399fbb2cb299fffb4041bff641a92a75d42a126520af091fdf5ac45bea9" },
                { "sc", "d42138f57271a31c885e3d2e80500471fdb9886b4ef7d33935c8364e27c0a7f2d53976d16ec8a22a9bf97acbe7b66aba8878b436a744ab8361f90ec1da69a700" },
                { "sco", "0deee90c3b1683acbfdb5fead3609c44814e5430dba5550880b2bde595130b878f71c24ec7773219c265b38e5362634c184ff4cd762cd1ffa55093df2be40fa6" },
                { "si", "d8b016185fc8c503c8317adf528e643cba07ccf8862170a230136600408800e79717fd1ac7d9a7909fed949dbbe98926ee264a53b4ab916766ebb5a3b1af2719" },
                { "sk", "1963f47b3574c4aab64c2b6be0df095a6282726e7bcc58066d5f885fb203e9784813b8b0d57c501ccc8d95a7e0f1cc56883e22260e347d939d9553f551a0af03" },
                { "skr", "ee46c769428c1edbc31a71bd095dd8bd690b2f756cc9e1c0a191602e250700a64edaca7e66514b0582de6e79ae43f0192dfe1ce6c8a4a82cd65324f712b6db29" },
                { "sl", "5ca323292f88d2d60c96e493fd7018371cbcb5f1aecdcb85541645b3eeb9488aba271467b65f56c4c9a5c231c88bd3c0f4ce9d7f495598f4be0ce1598ca82abb" },
                { "son", "abe7833533efcd76d97d7bd62cd74c6552ccae76befa63f959952810b9b126da3dc22daa60a7d27ee4460326ad5c097855ccf7f4cec3bb9989d0b2527218a161" },
                { "sq", "a9d8129ad0c3066d1618060377913337c92e58d4985650255c07ecbc5bbc92d44767de366a5a13b7595e118f7e41e0fc38b1c668f6b177b7df26a0e5abfdb171" },
                { "sr", "0aece00416b2938108bf52fa8f600e979af8263690e5af8c1393974c01383a74aadb2a40e193e60e3308ecc2ea69c630d94822b190ff5a14a0aec36a74668aef" },
                { "sv-SE", "50d1e3a7a49d5e3fdddd5e030b473df63b5847fd79a6406e204f65a1ac6c7646f8681200ff53d863e1e801db139c7c61611af93d90084f73d8097e16f966e6cc" },
                { "szl", "b84f79078f03e1aa135743662f70b65734353c90c8a52db1fef2342fcb8e70761edcdca20fe313d0da74bdadb26e8f466e14caffb4cd8a51c4720cb41affd271" },
                { "ta", "a289b0d32215f84852e737534a126621839ed4dd3b559b0b7400635ff7d7ca3699d28fa02a839af512be7794160c40615a344028c3fdf1c66bb9dac052f8677e" },
                { "te", "5815614afa5d200a07c3c1d4cfd9dfc759f7ac3b1ec73e73abbdadf09fc601551a3c88aaa29692d8edb9260fcde8287c743dfed9978570a92e750adda2409a9a" },
                { "tg", "d9b114f3fcdaf447eb1be21ee567c1fd5321743165f521af69257935081da77b3156afa2b80282a9ea2b29f2c7678841f3b9404ac8477dc902991fa2dba2674b" },
                { "th", "98cf17507eef14a5b4eae799ddfa0f63707a9851d07ee7f9472bd986681a3b573a88bbc2c80d214781260b27da2a74ce2160a59326aa117229c974616cda30b9" },
                { "tl", "5881305773fd85d2007abb969999607e275942370169c42319f7be267ee969829bb6f7aa5a0567e787172deff8819e779380dc6cc8895fa264a727c2c18feebb" },
                { "tr", "390f576c9ffd17674f624dbad402c64b5638c1c41b1a0e00d58c71ccfdcbd3c1c4f970857b625650b85aee7b6dd38844c8237e06fa0cc68fb8ffba2bb7503397" },
                { "trs", "2f08397f92b1b3982c2d4adf991239c7d3f7a4ac0fc2767dc1500338cad6eea42d284fd04e8a18118f06ec90703b6df21389102f46459d9bd7d25b5085fb22d3" },
                { "uk", "503829fd91630774d4cfb9c08099e33f6582bbb16157e6139438c1a4d248bef9271adb6ed27bbcd2dcd4ab944c192590851700a4eb9ecd21467973021e75e0ed" },
                { "ur", "b816f4f110cdf49116aad9e6c4dc4de9aa25c1c063c2bf4cfa993f196f2208efcc3b282b369d7f09937201f5cdd61acd13541124ecabfd777e13b04039838d7e" },
                { "uz", "d4a68c9f1461586b152a808c0ca44b3ee05596c63e46b348ac6e68129f2110dfc46073d23ee6a2f1839199d29709c08149d35acb99353416f94117bd44613c98" },
                { "vi", "16c45fbbabdfd5091fa39855c5e903bfa579bf0418a17fdce2a11b87011a8dc2ebf94fcec4106a73489832f24807754df61340e18a16d87b52f6220d980dd189" },
                { "xh", "e8976ac079f2ecb6964c66deadbd16bcd2c96ae1dcef0ee9f3630389e10d6bf0ceed80e3650490a6c2a24ccca4f1585637fac68a492cdd3cd8c1fe03f0e1cd92" },
                { "zh-CN", "86f9521dc8a82af442ccb882b1dddeccc97ad0b616467ff9bca5b4fe1a7e8cf1ebb293ec0c6d641a9ea7b3616ed49552124a7377aa50198d24470c68977ec002" },
                { "zh-TW", "cf712e86a3ac1ab627a06a45445035afd8c1b8bebeb8c25e72cc053f64203d1430d54596c98ae57e0d583e6fe5df124503edc453fa9dc0948052650843bce789" }
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
