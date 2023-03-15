/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022, 2023  Dirk Stolle

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Thunderbird software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
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
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            checksum32Bit = d32[languageCode];
            checksum64Bit = d64[languageCode];
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.9.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "6c33a395ca537d560620af9287c75430ede42b45e9aa56ed04b59c9564424a8659bfe8a148d854a3d1a735130cd23313f82fb8ef93f208bfde5d01e3d76cc8f5" },
                { "ar", "6cc20805dcb59a23ce9bfc01f46c16d9879fbab6c31743e50bc126cbd56a9a107c71dc656fc63dbbc5084e5de2dd2fa23280e68b533118a943f9b3dcc0f96335" },
                { "ast", "ebf55f230bbe43881a43c3ec30b62acb25e8f340b76591cf5ec4cafedbcf1856da8b1180a9c7d94090acd9718850db53562ad49273728233de3255f7a44adb4d" },
                { "be", "225c607dcb90a4a64c0361b9ce2687f318409787ccf5a5f8db543ead869fe9e1580783f0161851ba97c5f9be23e8bda787ecb44e9d3eb1f069ee92f2e4b20b60" },
                { "bg", "869e8638f13d92804dd4addc031520657c296d115f052ac6c9365d4c6da25a29d0e695e4a434733e9b7cc79bd9cea5a1b38726692880057d70edabddd963b6fd" },
                { "br", "4bdb7fe972250662f093e5985561ee6cf03c33c65665c0bbe5a84e2e1e9e86e39a028301206e5c308dbefae5358bd09d5e313a9718b70f7bef58a33f5c79e90f" },
                { "ca", "123db10ddeb032a7c1fa6b8b36b37259d068d81cb4c0118a953996c65ad5eb33b1377bdb20f6e9b9d15a6fe4a54e3bba42942e47a7b51da5e1d95b24afc61198" },
                { "cak", "47b783d8c0cf861099dea96390d493fa2e1e04b2117ee86707d470c0b835a36e1aaed39ec3a275ba3fa943ac74b0e9ce6fd373bcd642394df63b06deff21ff9d" },
                { "cs", "8a4fb51b390585c583f65b7adf0b29c1d1492b55aec7641a1799af93c39d2123981bea94e5bd48e653ef3be67fd52a7afe00b99ad6db9cec036668e43309a2de" },
                { "cy", "db0fda32c3e9b18ff54ced982b8bb1635d4378b07e4e7ede926d396f5f1edf37ad30c6335f3178b3b62f05b25e4b9d0c20f29a53c60d7af6f547b094c47b5cde" },
                { "da", "0555ce3d9d026e35f4b4cd1f983bdfe874b1c0ac1b042398b1d86136b129a6678e0ceeb01ff79ff35891cd52c6094584fce8843dc75a252d686b49967ffd2c8f" },
                { "de", "bb132f6b4c4e1ae016885d2a4b0a836ce3e5fea09bad20fb09a3de3affc66ba432f7ba231cdab4566c6b231cb60b04d7a13130e4a99b1fd52aabbd03cea328d8" },
                { "dsb", "df712172cb3b65913628ae2a2a194f549f3e6635cac3e13b2c505db582d2ba41cc65f96f7bb4426f2002c2cf6f8d12845434b4460294123f936bcaebfc425b47" },
                { "el", "302aa3fd0c9642ae507d9be1e534e025ac030da2ef3651fbd126388b37d79433c3a42c9bc45a448abc5ee0d2c24a3988f1e11759b8d61c57d9e1ec2228c2a20b" },
                { "en-CA", "6d8cefd7d91d018e2a27f879efd678f40d85c0008b38ad5437e8bb3c1a113674cbcdc9f63facd56d7882d62757243ce8d0ac58fd5265a5b11908a1d4f1e36440" },
                { "en-GB", "740efabeed30c5ccc9eed5134d89f2658fd642e9eca83166d17e26b12cefb160db525cf8097c9a5e45bbe2feb7cf00270f053e957930e2c46afca352a8de10fd" },
                { "en-US", "849fd0d11174148d8c164e20558931b024554ea3d41cac29e369c0f74151dc04c65ed9d349ba769f71465baaeee81d543fca7ba780825b9fd15056e4afcda41a" },
                { "es-AR", "23ab45fe359585373b13e40dcc5629cdf1136a33510e21aa3dbede1b926eb5386d2b4f2b9524f5e218480061b205ccc4ea1f6241fc751f20cf711e1f39344136" },
                { "es-ES", "a63eb2068c6b184ad9a18e6d658fe9ac62e77f4d2111fbf05fad01dcdf90054b1caf67853377cabe23bd9a28d5d813a2625b7cb5e8746a0b38dd054bc5036925" },
                { "es-MX", "5ae448324032f90bb42ae87f3126ff6c85bff811852910e8eb2623f0bf42c5e412d4bdc8b73e76ab33f545abf99d49c6fdcc53a40c307128bd6a737a58701444" },
                { "et", "d4cbcf36c3215236c870dd657159a50913e45e6aa3249a6e05664b61897c1ed16717ec7d85f0e439d674ce1694d009a0b9f7ffe02917148d7dba17bcf3a8c92f" },
                { "eu", "f3829fe13d93159b29282c6ffad980fbddebe4904f1b87a1af6c352be109cb06c3c9a8e0e2b25d82d8953d8172e91fa31429910f363fc0983c34b72f123d2d11" },
                { "fi", "bbe5a30fbb27cbe261d4d0e6117fdedb668750ec99b3bdba2a69ebfec60ed0ecbad1cc0193913dde22a834ba797d88d0d80e10034b038e96e82c111c577bb0fc" },
                { "fr", "9f05fccd54f6f37de43ad09caccae22fff104042dae4d595e18ea9045b3822a81936cc30ac123c779e667fe6e81f074b834b11cd290a782bbfdd822fd3da054c" },
                { "fy-NL", "c70795c9f810db013bf605943ed14d18f125dc549490a3d9b27198794ce94398ea4edb4adf388edfef65d5b225cdfec22fb3c09d045855df88a4b83ab7efe7f2" },
                { "ga-IE", "eff3207d6af8f0c622e87331f270670073f14c31d24c37a6c55b38164c757cfce7012cc4399ebd4154c8d1e9f2e19297bd3b5a283da94e581db3f38916d58814" },
                { "gd", "92353a5a5024ee4c78e55283ce46daa51b2ebe5a764ef87cedf47a172422b6ee402aa87db08fd4e3eea09c9ed7974ea86d36f34b3fc514da85b2dc62713ce8fe" },
                { "gl", "ad1126124292dbea5837d3cf237f801cf5a3ba262a814dbd8abe23892576e51bc9c9e699fd8fc640b1220d23c047aaffaf5024077e3ff3db9463b169ea577acf" },
                { "he", "2c8b6a2614d3e7ef6688530273379c0675eb378a0d57025cb380a775b3edfe8c83d0a002140330b1a8e4e6e14f319a37512d9ddd0c7222b153c11affe28c7d23" },
                { "hr", "31ba9151e8ea17c5e114406a95a11644c6218193a0d7943074d4afbf4282490a6d626956bca906ae279925bd5f09bae0b15eac65c1711908a3d824910b9eb433" },
                { "hsb", "56a3ea582528c256692bc246d572cd016ebd8d41c17e9dafb2099d9349f167c19cbea236e28800530480691ea99a6dc79e4f335dbf81aed6f67b6c62662fd8ba" },
                { "hu", "ba822a9eb84e85af069fb5319ca21003290b8881a719bb576d5184733a94155990587e7f2444d5707679a9fd13bd25f7513e920dd1f1d6b3fb5509ab97cf9434" },
                { "hy-AM", "0d4f6bfd35c1ff99154fd050a03915d1a0c0ef5f9be18296ce7d93d56c5be170d2a6228dda973fb8e060b77887d85050f174ce49a2d44e87014f8adb4159914a" },
                { "id", "f8c95f730e27b969127d9ba530cde2411ea248e75348a69a8b08b59a373a9fe542f9cb8e0782cff7de9fb62d46d4de5265d0cd70c1c8c227e6d934176d8e01ea" },
                { "is", "b5aec4a35fb13e6053ac51bd8596aa6e06d990d16aca6f7b11f250e882576c831ce69c3a55d601651d59c0503856e1f720bf02e1416b02ced8833ee300e63a0b" },
                { "it", "c0f81fc9a24ce7e051252ce40fc859619c90a1baa72f7f8e91571efefd274e0b608b25708921b47adbe9ad45333af66c3fd30071a2bc55434a0c9d846c1d6b21" },
                { "ja", "49eacb168a1dc2158419dcba25ce2b559287795551d6338242d323f5bae8305600852e19db31c7d8ce14395b80868e9023903523f93da99b998d2c9be739c233" },
                { "ka", "e628bae83189f306472a8599e36e5224df00aba23dfe6ac563076bc1166daa6625b368d22b101ccc850ec6c7b19b28ee516224379d5afd885d31da3cf44a333f" },
                { "kab", "89ced2e284031fbafefda0f680213a51a5465f61721b36d70d04e11c499a4460e2b906239b7b12b06c677973f25801eeb0fb5e1bbe7b8561144e8124ea7f8300" },
                { "kk", "1bfbe5c1fd7a29141a41352f13962fd01bba226c07a6ce19045ba1dfd95b0482f54d7cc8d872c61cef487474f1c0bb3c7ab693d830fb6d2b0d04b5112fcd486d" },
                { "ko", "bdd4772899c7867181ebdcfa04347b628d368b8769ed8d543ad1939089d815609f0319dadc7ac1acebe1b1fb924f70e9bc3e81cb893aab84cba0738290f92c1d" },
                { "lt", "9770ed1759f0734ac53a2814a8c1d665003bf52d55f6b642276a3f2988dac3a9ede1831ee63ce3f51981683a90c2b5b38c7d5dc87e4cfb78bc2f2c7c6e2aece0" },
                { "lv", "4f1298e4d0c89fb9a5429cf47626157c6f42ac62dc5cda2d2967cff26a9bef1b6b7f24725b3b978ce6256ee1ad50e181872d623c719671b39cdc3d4f42ae5809" },
                { "ms", "298622e07ddc7a9caa90eea01b43d86814c62255d8c9266125067bb05a1b38b56877ad3e0b25f2d9ad35f137874ecbc14b97c36f4b5d2b83fb650ab490263a9e" },
                { "nb-NO", "48b1ed78986230fb576984eb136fac1698905ac539c8ca8c4655fe3a281f89603fe050fc7ecf94dc5f7fb11119101cc8c2b20107196417d7fc9f597b10298c11" },
                { "nl", "001a14a7349e95348f02ac3f20c096ce1643a275e8b5a43d7e29a1b94cd073776eda8b26467a3df5d933f3d5169fac1675794e1d85ad5365486da866624e8c47" },
                { "nn-NO", "d90a7f0350e3f2006c0e209069f8fcefecb60b4fd85dcafcf47aca164002e90338b021a6806cc97acff514a422a76a34a3c7f9c0d72874bd0fad6f376db7febf" },
                { "pa-IN", "be2e1cf23fd1fb9c3bf21aed8973564b12fb7a96caf81318f2977fb78e5876ab34a28e7f470b7cee500f662881f861848cc09f5b0146fc51d3f377408b8f06fa" },
                { "pl", "782001ad38e46022887bfd126a216d64e34b8a9b9515ccc0b6bd4ad69960a31df82cd5f68c5c46ce83927cff3942a842eb11905826908c7ec672d583821bc8b7" },
                { "pt-BR", "a8a2dd94be754750969ff21bd74ce51315b4de2df5a9b825500fd2848d10d574e7818157cf8ae47e8c5ef2e944e74db06413fb88c9bf60c2c16d822d58d6bc6e" },
                { "pt-PT", "5d2d32179e1fba7c282f6e406382c663078ccff0cda8f72451ebd07d44b2a1de7f227f4ded440a929a6cd1f9ae9db2275f2a58352c4d560bc300ef5501643e0b" },
                { "rm", "0567726427fbc2a233938ff4d72ddbb9f2084f8dc6091d6ce119215ea2f4413689a308a338e29f471ae6ffc91891f017db6667f6fc39e250c092d47c90a1942c" },
                { "ro", "494fa451fd30d6e139a3b9be02ffe1973a545b83b36b040385a84528272fa89625915eb69ab62ac5e23aa7f54ce535a4d9e82b5c017af77b430a1d4b0a3fbbd2" },
                { "ru", "9f4096a02fbe12e41717ef3748b9fe675cc8afcf639fefffcd162c0899b14c73949f90beb076f478060c07bc8880444db0ea65e2e8a543b92e3df447e1239f31" },
                { "sk", "78333a80a93ae9285d32f0a0e24bfc0080b6eac53b6feef4010d778ae6faf9d8f3e95c8bb8dd3a1ef84a5d02bdab8ec6612ed75f0e4233c4649c65bdccb26e8c" },
                { "sl", "129ca99d921872b841401d4b91a0678ccca50c901d66e986414760a0b37b5571a4d4739af16f9ea9f8017d7dc5f165b3a3638f7cdcff571e04ea9d481c6f7672" },
                { "sq", "ebd26629e04f62d742cf7f5db5c25f19f5fdb68b46cf5048030a83d697bd863394cde7ffee0f890158e5d4b700df97a3c139d88362937c6d983a3a3c9c71a1c1" },
                { "sr", "d9fcc25bc4eecbb239903c16a24caaaf8ae6053d41c81696bb74c78a5690036c11c69e836c5e02de922a58a24002d1d97f41ec04f76f4c8b68c5e0bf167e4166" },
                { "sv-SE", "0a5bb4b9e2b6f5d7721484df57efe882a34830c66b0201b0d6ce509677d54af9dc6bc84275c0d1a17a60abc2e50477f61266f1b024bfc234f6cf746b56100295" },
                { "th", "eec1392bd1cf383b3eccea513b676c84fc371ad928b6b33c3962e4b728e6e816521f1dd3eb45a7a34a42fa10155d8cb9b55286ca50a1bdf9bf99153aafa6ef3f" },
                { "tr", "a9307e52fd93479867d9074fc5d832802956cc6c283e320e9fea08aaf63cf781ea01d5ea8faa96ced249c0138dc8590bdc315f9b6353f1e6e3f2ad91a7b805e3" },
                { "uk", "10bb55084b9184ade07ab206be17399db4a26322997544ad1bbfd4b9d40f75b13da4cdf00797beadc3ffb3793286929a1cb6e8665fba167a6d756e29a52f9cb8" },
                { "uz", "5489d5f73921b13c38fc8bda842c7acddb5096d2d18d9d36d8dcd4a80501a25c6c57a5d6c68d5b5bae02cad9bd68f49c7bdbb6ece59813480902473262b8a9a5" },
                { "vi", "e9f633f770e9950de12bf16f2819c24edddb971bf9e8051926a8427a4d05df771c6ac0ee9dd6c87446068c4611f9d55d67e5543084d771917681db28bc8f4f09" },
                { "zh-CN", "ce5a4ef118ee14d5f82cfd72bcb5648a5fbb9682f2737e3b864365f740a02732ce8fa27fb927c90c4bb0ac9fb9fccc4cfacefd5cba77c8753b54ca2cd4c4da5e" },
                { "zh-TW", "8fb1a4abdb0af7bb4171d1c26a8b5fa4002213c0f83e73abfd9c33b7bba4d21041f1b733b89f7c203d7377ff8d58a2c1c8b51b4cbb1b84e1f49eb410a973ec39" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.9.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "e43f27898349ed88ffcca633371eabfdb1c5c59324f15af407fbc77bd4f281dab991e4a6d42176fb11b1fbfe2014f335acf7b36634ea29aebec30ebde1ea130b" },
                { "ar", "70f42d81df50ddec1ff753ba18aedae34c80624cb04d1e67d9c56d05dd34338cf7a3034be046ef3cc5148ff94ba27a0dde97e98c036b873238af94f5df856f8c" },
                { "ast", "e341377180e81ea9c1722b23157c16cb17357eaaeedd4c04ff5f377f6ac6bf9e917a658c7f497cb8cefc5bebaae2e12288347f0ce7fe3427e03778397d9c684f" },
                { "be", "9be267c4b86f3240b247f197023c81dc2f32b650d8a3926feb1027090e7df1558e0ef552b9df012c113e43fe87da86e2166590695dda1371922c988d52effff8" },
                { "bg", "f42243b170b492c6feb824ab79be492fb0587f2599508bf75da5f7a6b3c3cea6f263aa279a38a8a49db39f13fb9457a7f6dda8402b9248c01cf89ca6a2b8c3ed" },
                { "br", "fa1eda10cba35db234f02ff516933fada29a8178c707535017d973b41b481c55c2aefb5061ee201827823e9de524fa2f0fa0618cdf6304e1a990c0df107ed89c" },
                { "ca", "e239e52f53eae168e890d46c203126b2dc05a05fe76a4c3299fda386472e490dea84064888d10a03400e11aaee237efc06987a468e1b15fdb0736e940b405179" },
                { "cak", "fda98e2f13e4c029c8855857ed4f3fff243a1752133d7e49ee28a741c352dda27b1d0c9317acddc266e6cd6ef086841e5cbfe7f47f1de9c12b81308c1ad13b05" },
                { "cs", "5be04b8970b7188f45be24697eb0daa7627e28a9f7911c35343eb7009ed879c73a76a9eac3a7cc92bf6967c87c427403e52184a2290798519efb4d8ca7fc2300" },
                { "cy", "350a4d2107449a853e27b5e444f61e6e671efb811c6e0c839c0870bcced0bbf9f3854c342637b8906f25cf279a3d9812cf43175a9d6f845d211d2432cea2fe0a" },
                { "da", "a3f5e524f13d8a265f0e0f4bb1d9b38e61051a9b0139878bf352314b80a79b9301ed56d1da1ab0bb63c05daf5b90e952f88d9f21a82040aed6e51bec596741fa" },
                { "de", "55c39ff66921f5118e9607123669d150186f845aa369ea044ffd1988d2c240329fbf042b610ce1296b9673b5882ff469077eda25bc2e10601035ea9615d353e5" },
                { "dsb", "1ede85243eaff8d3afb3e4ec1f40beaad1b2956952fd0f09b91f7685b51ae752e23f942402dc0041382e3c282a6b61c4d9696548a5fddc864adfd664313b504f" },
                { "el", "57459e69019538bd825ce0aca137ca4ada311c25fc801cfc4fbf177e409d1dd820cad2392fa878eb9be3b08d6daf00abdc1d6c849ea270dbd1b472b27dd24aaa" },
                { "en-CA", "2a49515d853981a30cc38437410e8e435be64352ce4e512afd607afdcba8ba1f74e175ccd2d3c7c6c0d1e17d18d40cc5f7e019ee973f8ad616962a6fe9137c24" },
                { "en-GB", "a6f5887c324613cdd1941d273cf16ab65d89402ed76cefa7ea41555ed32b5fc4189b08f7194b14d955526db8cdd7e40ea587757c272300f2bdf3cc34021b68e9" },
                { "en-US", "581b61551d3b39905df052028740f56c08adb98cce83567925bdd000f9926c2a7a6635bcc508cd6a42f99d105ef2c116dfc502c5640a149f3e811656f49ae907" },
                { "es-AR", "baad96d7116b1cb9876ba9df262123ef94481ef3bef511798983dbc1316794310627db7489af3c604c30e9a7cacf772b98d8976f57df0e0c4c7fe2d753738b87" },
                { "es-ES", "6957ddd2dc266471acce771b986506077c3d68d9ad96b621e3bb2d49071b0333cde952a33d2db3df5fa358e96f92179602931ac88735714333c5bec5352cdbc8" },
                { "es-MX", "3e1225ab0ad9015b65175d4e9ee07ef6d0ff6bece4cc339f8f5f7c8284ae9b7ef128bf41bea0190e2176ebcae359ae57f9ff402e5d255365ee8164aa64973e8e" },
                { "et", "dcfa332a3bb2c13ab725535fa14a44960bf4edf4a7b97df9eb49facb71e3f5989641f2bb30469cf2c1c6e98e4863b342df45f5bab5d22eed9b0153abd6709c51" },
                { "eu", "cfd1564af33b607b7e0333a98c1c91699786f91ef99af308ac47ab1126a34b37916a5e33d72d421709423bd6c89f388a7026d8aa7b6295ac10b51797bee030ff" },
                { "fi", "2714880183275ac9ae5d1c7e6322362c982b66a961eb57152ea27fe50d34ea1c8ce3e5576ed5dfdc8e5d6b7838edf9d0b88042c53f8f15b08f303d99dbb2d113" },
                { "fr", "0ffbaeebf29862b0989ddf0c9c063ebc7e8b9e676e30251d12a01169f0de926558a97347c21620d54dcff7a07b94857e002af9c4deada850293cac08139df982" },
                { "fy-NL", "75dbb5d168565117cba89634e32ad02b3c39a69a09d1993588378d2088af2ee1926fc63fcdaa8e6668ca9e22bacf77fbb7d12a061586649706c585cc2ecb733f" },
                { "ga-IE", "ad72d9e99cd8d5206f18f394cfe7895f439d3d9dfae065a45de1079ecf1a27901cac930b869a0ff067330485b6f52ada013597c7b386de4f034011a34c1d412a" },
                { "gd", "747eccc768110154cb328553fc4dc9f0775c9218526604ba2ffab75f531495b4754095c98b3c48ca1eeb4939379925c1acaf5fd54c29ff9ebd87ba593172c8d0" },
                { "gl", "8cddf58050d066237a4c156678f62dbcddf5075e92f2f01089c2c4f30cf6e133d74eb824f267261789a96f9186e91776cea7dfb9f0ebd2501eacc7968d0cfe9c" },
                { "he", "81730767cb51e9547682262aa980446c99744b202e0fd6f21814f143657a4aa60bcb3bbe7ad35e1324b770c312baedeebcedaec1ae6ef2a401f3454a853730c9" },
                { "hr", "4fc915cecb1dd23044778c1c5f6022fabb234901dc65f855b4d1ec65f1e62c300c785912614a1af7dd5abb24e697715b5efef90029e396e06cb68a81d1c75cf4" },
                { "hsb", "ce690d3b6f5ec65a0e146e578a7ff42f8d2374cca00e4af96fef24792c4e35de0f62ff468da0109b41cce66f1724c58becec99bd2153f865c582dd834f35873b" },
                { "hu", "0f24a1df3eca67fe16ec1c8e47180e1dfd4c5990206fded0bafeb998b3793f2744263336fb51bb5b97dba868156be4884c8b7ff6d92857f9121f9d79c9efb9d9" },
                { "hy-AM", "626a5f15a15915e873631416b9d1b34200089d9cd13d67b6655f97b7ef24623140c6f2876dce95ef63a7503cf039f20eeaa273d63ede60a908a57023c01a2dee" },
                { "id", "5596ff963a0170d18b820a5c65b4a0e8c41028571a98c4c33345a5586061ed3c81689b1abfeefb8f670cb6ec6f71541e0ff5c2d6c77411938f1266cb21429320" },
                { "is", "f2a92fd975d0e28416c32d0b8c560d70ec171d749ca0217aeeb8e56a702200a8c3e18a1226f4dbeac2baebc9027951953529fcda6998132b15ceb8f21b0d024a" },
                { "it", "ff512a09754722c9f6f374ee972b22c71126ab40905cba4445cbcf6ee2cc5558c7a50332c85c0d1c239a7aed282e08928d6588b6f9f9702fe4ea4dd8d1835a7e" },
                { "ja", "10829ee1bb971a4ea5101dd1c68f3596003bf537d4b7486ad757a04cd8e94f1e45787073a2b431bc15b3e50aae7381e71d81d93d9fb15a3e0c9060e2ecb2f5b6" },
                { "ka", "e755dccbc63365618f25d8395b94d5046857083415c1890246c9c0b6bac5393134021d50e4f5ec161a9859332d230264eb963c6fe4cbbe464ddce652b8f1625a" },
                { "kab", "31414f6e37f834fa6d4e325e9fec34db7512a2cb9f33993dbf79430983ba50f11a4d7c0a69747436f65b12d0f42aa59e84683768ec6831e5ed75dc7abf93f9f8" },
                { "kk", "1a47c21babc696dfaf369cf99618ec198b56c1c35d8c9b162d38589dbb83a3aa4e5c1bb950c2c149e4d19db86ac7b82fc24638ed068aa652fb634c9eb05d2a3c" },
                { "ko", "52fd9d171627b4bd6b224e7b8ebec334bf552af80200c7f87ab487a15401a0e6e85a6427ff05eb59cc3094731cd59d687e0c3a3b48d596c8210d534d6eccc811" },
                { "lt", "d83cb2ad139f6af25e70abdf6c5181c01a342e5baba0f9e57d40816f26f92dd2ed75f90d4ffcf4c41d36c9723532c1bfb16903e716bbcd3fc1ad0058d9af1b2a" },
                { "lv", "8a39a25b7873eeb3bfa5ce0fd5af800fe45ff9f468e123ddd38811648df959647833843fcf2c98cbc5b3822dfe12d9e8e8a2b6fa9ae136f0fc54cca27eb93aa7" },
                { "ms", "35692695f874c12e939cb6ade0030b0d0be8228cb01dc3f5c28845d379fb19c1101e690d8fd65cf1bc31f3c893c83e57ea7cc6d2a200d0b167f61faed2afa661" },
                { "nb-NO", "315f052c3fbff5d45afc29349e04bd9bbbf9052f47fa3e0a229806466c1baf4cac1af70b16737242e5e111a4e7596a8b9ae0c3f3736c0dd265005c743516a76a" },
                { "nl", "d5a28e88860bcd3cd30d5f5da2eae996cc1cd85560c504c2672604bd9ba32bc1ad1a1e8c1436ec7ef29f5cf08326386fe7fb85c9ff7a5e0d70ea746ccade474f" },
                { "nn-NO", "f4b196f525c2c8d222882c4c65bd6517173242a9cd7ff03ca9732d97a4329d4db4e0ec71f8016f409820a9e8ee35c96bedf3cf09067670eb7e8e4699e5609dd0" },
                { "pa-IN", "c9bbd00222d4330c6f54d4346086f3967c73d0fce2939b614d04a9059d6e60d017d8309ceb15196872dde5a28e8840ed23a6f8e4e1d5235d608d87379baa0642" },
                { "pl", "0e8acce12be6c118b3042f207a1e1924d941e05d683e9f098cf872f6f451d27eb78869da51084d5340c2b3ed867b4ffd0c729db3faa81039f01682ff31a7c11d" },
                { "pt-BR", "eff5426b6cade3bc8681bfbee7f106774ba3f9c10100aba8606c385fc41dc3423916c44ddccfdea3117dd516745fadfc59cbe6f1b28fbeaf88a3c66dc7cda34a" },
                { "pt-PT", "97d6a118307153045962d8bebb2bf919c2b75eff29e59c2d134dc962263405fe5cb26f0b41f867a8dc446264da3a0ae78a06af67068e0c4d265c2580322e701c" },
                { "rm", "9c4ac3e7430adb50b929929667f11de284d462054afd2b127a2885651a3ef7bcc5c6436102d36aec64f34de85ed824f55f30303a86a59daf3444a403f0e09259" },
                { "ro", "60f5008f33879d8400d29ca628b1b45f1a81959c3e16caebd702200fa6a5f6bdcfd7dfeec21829b2998c2c3b9d3616a7f2fd845f6e7270f0ad54a556ebfdc7ee" },
                { "ru", "57a90119dfa7bb1fc66c9d0489558c254f59395a9af84819570ceb1f85c381bcf1fb0e5de13e1f8356fb513dbbcbb0e2893577aea9588f42bb6f9ea7360e7e4c" },
                { "sk", "3b6314ee4403941e6c5fd14d9b08ec5fdf4a00479113ad870a49f028b602e0731f555c6edc9620f6c9aef0383f5e8548c3671fe3283075d362b2fc65f4917539" },
                { "sl", "02255931de16e6ae7f62b54b2d55464adad69f55fe896a0308235dda02aa2a51e0302d9dd098d4af5b5942f180e1453e3e6b396c446a431667ed9dc78da97fb5" },
                { "sq", "5cc5d91aac9290b919137792d25d3bb5356418ad574f4648d6a235b92cb884b8e98d7d980b36bf3c6036e58d1a7dc5c2d42efd16e627d9dff6ea05a786f66bc7" },
                { "sr", "fe848ebeb1093e53348f470029c720a790decbf20a1bd871accb79f610079e3120d70b40d52cff2a8aece54317fe56445ee555bd105486db5a36095cf951326e" },
                { "sv-SE", "0b58de1eb04b20ec43976f217f049dd27f10229ba41a958c4885943d11a06c32682aefa21ea2c94f9fda882d4f7f486554698c4f22650e9df25cb4c9cb1bec2e" },
                { "th", "a7376f30f82d070154e3c0f227efd2a56c4de11701a84996ce7c922b0ef493317cc350e355a90902b9757d97130da3326ca4bf3837f68553dd31110e39665368" },
                { "tr", "2e9551680bd5ebf903881207bf41c9311b762a199f60ea4f01bca8457f4e7e79a6d1ace3ca323c72dc25168a5961439658ffa5d6ca2b83a5cf2e6890cfc8b335" },
                { "uk", "d198bbdbc2558ba542dc8be2d3149833009a421037d725dfb7c1481c1508a60739d807d4c6b08cdfabcd41c81bedcd36ef738250ffe8ba3faa793a3de47a2ca0" },
                { "uz", "70216f3ef91151447c0fd9a9998df23598627b3d07caa51f2fe705dec735b2062daf3d89639baef48e36214bc8948e90369e24a5d764aa58e1ad976cd9b0be0e" },
                { "vi", "19148feb67b8337e2dd8b72749faaa0e369767cd665210ebb4c457d6f10390361cd52668f405876ce36e732fbc81cd68c82a1e12b06591df0334b71cfa30f1ed" },
                { "zh-CN", "1250c47aff08e7e466920fc58dd26ef3fafffbf11b0346e336be9ccad0478ac598c9470881f56a85f9d4f3cf8e6b170e29668341bed4fa08a8bdfa25a8d12b7e" },
                { "zh-TW", "e47e4bfe712fb6a31141ca73fa9a9130c547d2e17723fd602bb7a54045b3334494fd625563dfd4bdb3a4a263a5f83d7b5eb9f216247782c2b3ed4e781e490bba" }
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
            const string version = "102.9.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
            return new string[] { "thunderbird-" + languageCode.ToLower(), "thunderbird" };
        }


        /// <summary>
        /// Tries to find the newest version number of Thunderbird.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=thunderbird-latest&os=win&lang=" + languageCode;
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
                task = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksums are the first 128 characters of each match.
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
        }


        /// <summary>
        /// Indicates whether or not the method searchForNewer() is implemented.
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
            return new List<string>(1)
            {
                "thunderbird"
            };
        }


        /// <summary>
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
