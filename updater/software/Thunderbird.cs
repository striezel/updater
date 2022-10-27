/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.4.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a392dd0b36c65c823d51c55351ebc6b77e67975c447f4b781c7d7ad3ef63293c4aa26f72d774dc2348a341ed4395a7b0c35c52c9344b4a673f32a80a8c9ebd11" },
                { "ar", "bd397306ee3f493f77386ebb9945e843d5548b2639e3bd384d6c75d2d61c888cf8ef91ab889432a8acddd2b48ef10073a55188341ec0b3048a2c9ece16b023c0" },
                { "ast", "ef7d48219f18fa637aec500c920ee9813dd76eeeeb6cc6ff0eeb47e79b2c081bb7964778bd9a2f6da5142c3acda50a991498e22d945e4b333055be6087dd5a14" },
                { "be", "211a336174f2c92a14fdc9fa9b5cbdb985d5b07a303ab77e5d3eac0e6950062b16e5e04750170edbfc09c6ff3b7ea465ec6161fb0a5db4573b936a11eceb1a32" },
                { "bg", "c24927af3a3457bcd800156abfdac7a0c5339413b7c9ef97233bb99e9bc43e720cb618fb8ee3b36a9fcb7b2606c10889535063a6f2f912b6a49d6e8e7b539b31" },
                { "br", "3f6dd8b57fff68451f6a071aaed3e1e0c99174624d344cf1b0b3fbd53f4bf1ed4225ad75cb28d4ea7b6303a1256707e2cb26d933568a67152d97bd35f2acc7bd" },
                { "ca", "e51d18cc15b4cfb588db55103b6cdc4de93d8c5c3748782a919c223b51c840d572641028cc949ca2e9933d4e29e064b134c768c1057b0c2a7b9b9eae71ed7194" },
                { "cak", "2a5b5529ffdd343f43fb8795adc6ca6f006300c0ef2780bd3e7daa6d60e977d1722b7a75ab2b9ac96501cb9bb5ebb9989835c38dc93ea54b0e11de4f4ec8b453" },
                { "cs", "5e14d7cbcb115bc46cd549096d1b12c11516aa556c746762ab6a7e9ad0a8f3d118839e353e6fb854b088f75fdecf879d69dae7c5be815ffce98ef6317bc93acf" },
                { "cy", "76d941cff0cc1fbfb9b6ba22e5a4f4d6aad39c2efff995b4a3e122946ec9304f2575cb504923967744d8ab153bf78ad574472ccae304991e14745282d038859b" },
                { "da", "ab95bda7d99550f44e3904aa5e98abb71a0b853c6806aac11675a98360d6fef646fe629ac62f61f835ac59ba744707cc9fe7d961a546d6fc68b5846ec3a78c9f" },
                { "de", "a1d00832e257c4c7116c2e61440ef0db33ecb7ced7b170b86cf64d240e968512d6ad9f8b48f6f1b8f478dfad71ad813ff5c3a5eb90d2e31487b8348a8780c6b4" },
                { "dsb", "dad145b530b45bd1e5e4f7cf63f5f5d62881bc36a47a99e68875aa2d1beb0bf4c6b74c519da1ad7bbf4ee6da9cd8ef0ce0939c26a98fbddb1c6a924c317a4a06" },
                { "el", "d77aa2bdcffe0b5331f7a00580554f00112d09126985adad83849bd1e5d164fd2d10422e29f756f5cb06714e61b6388677a651d0c99ecbcd21c10660d02cffd5" },
                { "en-CA", "ded184469b2348d37e41db0853bfe025c6de4c48fb242b3b743eb32589e4ebc3b67f950d0bd6729714d14b15707f3fb1b5364c931cc207d5a799e9c6ceb7dab1" },
                { "en-GB", "874470d7b2cca7f1a16109e9c8103d1643b86d68b3d6af60b3aaa87e6e5abe889c641a393cbb98a84eee433c1722866d2b1dc74fdfa0605a3262a234010990f7" },
                { "en-US", "2e549e98078659fcb9d7f359e9488d13250699c64907e1be5436dace76695849b42d5ad686dfdad7785a69720651fb2e2c52184a7a1e134cd94291b7d85e01e3" },
                { "es-AR", "3c5c85dfcae295bf3c07c42da7480a01136f5155c8b15d8816c96e66aa971d209d8e484aab1a059d300bd6d6230b118bdca308e1d8abeb93a722da90c32a6b43" },
                { "es-ES", "c49ed5c7f71aae53cf47e7dee728a7f7a35ba48e7e782041fb729014cd0d3e163104cfe156ee7cd043f47cb07e31b6e3826e132d8a3c5ed0c853837b2b079939" },
                { "es-MX", "0e0a10b2c7498f13cc48abfe1802aeced90d05b67c285fd66c8e0e8b822bebc4fc4d9c4803a97f81de2dbdde128dd53e0dc5902c6edc7cd7005006668971cb59" },
                { "et", "f87e9827e5b99d669beb8d74c5ff4c85ae4dd465200426c6b04ea98048d61f818438093b199c9fd9f1da2124f9f9b99664657986d75f17fb481ea8bc0f1ab0c4" },
                { "eu", "8acf8c0f4f5cad5ad2cbbd74374423e217151386ba9a3ada21532cb841359f65b1576b93fc93e1abaecbd8d7a8c7510b45c05bcf76ab9d99242c3c9dfa199a8c" },
                { "fi", "7ada076ca0322d8d4a4ca43259869aa0c3d697422cd0f56b579cfa745abdec671b4331f6ed5e6d6a2ebdac8fb6982429ecd32ec50659c2922e5eefa0cfb04dc7" },
                { "fr", "52efbac45f4ab22e4d2f9b93270021351fa115b5aa5e9046766b5d2165490f235ffef92d490e68645c7845795f5fe5eae1755dfb643b61aca9ccb81fe234dbb2" },
                { "fy-NL", "8679c9881693e7936912b91ce03e3f1602d9857ec78dd29aa39069e8dc783e01bb8be6d0287075cf46c561a5ad492edbe05133fa652555692652075e5985e50d" },
                { "ga-IE", "007e024028e6bb6db4e845ab4afd4a0b19a97ea4a8b12ff6a02bccd83210b1e60065abbc9e93059ecfe529558d4765deb6c9335197d9cb78f5d233e3d481bffb" },
                { "gd", "eaf553298432769e2cfb8a5907c084c5079c67a891ef44025b1735c7c60fa1f46afec021cf1db40f9bffcff694b18a26ea3c22174af160ebb7d34de3da58ff0a" },
                { "gl", "cceb9951d9eb3be6c8bc62dfc1f164bce66f0809de8fcd7ced9c58a88299ee85e37e64e53e83a4c0bef1bd40e44241dc170f296f305bda75e7d2f6c1e984dbcb" },
                { "he", "102c038193210a6f7f298d2af0d22922c363818f0946d6d0ece62b1b6e59ada0cc141ed361c0a9da74e3440d7e77c7866da11635d3538443113f8d88b6226ab3" },
                { "hr", "dce83614f1faa2d8b6b8f703b7be4e5435dc2de7ccff01c089644985e22f0e2e7895958ece7e39ac442eedaaa4bb82a4852ccd5ee4657a82c4d38b7468e8c6f9" },
                { "hsb", "dd46a3a21d9dfa23c669860e9828fc84bf64e5ab6744577d547892285a449cedad156cd2ad9e298fc12558eaf2fd47345bc1be0f45682b4cbcf24968106473e9" },
                { "hu", "ce744389eaebc99bb1c98d0b4df2acae75201d91cc10198b6a9650a045efd8cd1c0a5ba833f10ff194f2a40b99127dbbe7a7bcbcb5ed627ae3619221656d13e3" },
                { "hy-AM", "9163e574535359c16d6798e86e2ce171c5b1c77ad66163e9b6b1816c3545565afc958e9764c17fd8861bc452a2e4b0ca3619c408c8cfbf1c7b81404aa6c5dc6f" },
                { "id", "f50276a151385cf583412cacc6a58c023e35231e6fcc63f63327e7665317aa788f6a00f3ac5b0920187aa1ab94642cee605f5f9b253b60ea882ef8ec6ad300b4" },
                { "is", "95b45c6372104d1d8fc2f47215b5141bd4300306842e5db6a809bf79f8c500c11adaac3da7d84d54450cbdc433c8fb1a0b03db35656085fc9befb0c10ea317c0" },
                { "it", "7d92f8aef4ad221dcf46aa0d287a87e0d356fbc0306d509326abbc2f27dbb2bf96990e6747be6c8368c7dba62299ad6c8a58f81d559d2e8b900f116bff8ed687" },
                { "ja", "8663abc424dd8482a04fefe454d846070f6ed8fbb930db9d7fce35854896f8a600f059e495c6e3035c3281c091b9f46f1c29c3d729abc980963d886ec950b38f" },
                { "ka", "05a15375565f023b13e4a4f6bdb23cf5f396acf5e49b65e0df2b242b8745723385b11a7a93c7b16becc9e0f4b84df05a9e28424b7af6847a8b5415047f12d945" },
                { "kab", "a856b3168842b03574816adcc808f4f2cefabc52f99d35b6473d144bd7e5d91c4407d26db7bcb63fc30995ea8a399a9f22dd20515a3612b647f17051ce838ccb" },
                { "kk", "d699f6ff585d06d34e0f7585c511491200234ccab5d3c637483fe13dcde99f56a74361b459e037d902a7c6d75a5313186b6d240598367098976629762764b2e5" },
                { "ko", "a727ea5a7c3b2ec72f5a92365c0a307d664d84817596097e53af14a139dffb9b059f1a3cf99f583d6c099a7557eeb1183ae3e8e4894831de1723372a58564797" },
                { "lt", "2d258ac4a027a8f25f5db9cfe00d2abdb00a1d4e4d339be9e7b473fc879e75f44c010393b7799c19fc4f4cf10ac4c8b79585459f2d9b231f4797d0c2699b61e1" },
                { "lv", "6f25304d4efbad7a1e74584f527b0ef92702f6838143ffb2faf91db45c6baad5e94efe166ce0aa33ac99cfb580e30278fc0e3c957ec134d8579c8bafab8a6aec" },
                { "ms", "a84eccd5032c73215e2d220aa9bae25d577f371268f20413f1ff1138cee78a3e61d7bfe77bf94817d95a61e02711b867ea6f735d6109460b4f8c8948648bb8c2" },
                { "nb-NO", "ad48ecde05d0a4483de288f49bd779669602857d79bb1a86e03850b7491e5bfe3e161b3e2b04020ac5b2275b2cca6e694971cc1c44416070e190893c50e31794" },
                { "nl", "c564f285fc954d666af71e23da13d9d8a4941d1f5b2c5cc6478bf5854510f20a6b390c1f79378377449736b380a42ae4137136076632324372a346a62727ca0f" },
                { "nn-NO", "6fb277cc46b46dc421894861443cf89766f3ea54c0cd7bf49b7d8ce1599c64e33c8a18409206dd2c2deaff5f0b41b2397db73c3b5950c8d7b2e997d9c274e6af" },
                { "pa-IN", "93b78c9d190ab81e35207e5cc0940b28741b67e15f94ca4523e5d0647ccf16cb09d712f467d2903647301ee9bdb18d56776585b46dc74e2fca3f9a67dfe1bcc2" },
                { "pl", "1781298294befd3f00365866ed1278cb54113a6369e104379b4890e1e6bfba291d3703ab2144912fa608921915842ae113cac9d7b7346aaa3ded5cab28cd2550" },
                { "pt-BR", "00fe295777636ffaf822e947a1ceae443dff6c534e1f7b2a35ef248bdf2a0914eaa70f9aea2fa5444d715657dd837c0f4f05f94e51ba223be6b861e9edd2f7a8" },
                { "pt-PT", "ca1716e139b33970c804bb3260b470a6c9de6f496a48e1d419c805ff1297c384701b943809d82665471ca216155733d87b3ed8f3ec88826ed092ae31a4945c4f" },
                { "rm", "03bd91fb42ccf919a83ff109275156950908294cd67772033f437f8078491d594d92ca04c68101aa4e7a21b27449e4566aa0947d6d03056967c5b9047db78ef7" },
                { "ro", "00407e70c04844562158379b2496e438d032e56fbe06eb26f10483c6a136d692088c509a820633c738d526050302e20328b46ec7befa257118950150585e91d6" },
                { "ru", "0157a271b2de91c1e3f20fb8956bee61adf08b765f5e95037da7f320c92cc4f91cf0f78e468521d2e4b48b563969a5d9bc9b8d384ad9b707d06edc15b5117074" },
                { "sk", "76b0ebf957606e40c469fb8ffec5090b513537c6b485a65f89494d8f8b09b8373def7d8fb27654d717b0a85033174e430842150b57b960cbde2d513da3b2c588" },
                { "sl", "34f5709c00f0262baf285aa50065f588ed68e2c6ea080a22e70add90f3094cff75aa03e792461f537d2c37fa9f7126bd4787e6bce5613b5d05cfdf6b5c5c99b6" },
                { "sq", "a1dbb173a91c15a3b5eff4f4659eb7640df3d7dd09553d56b8a538d3edf7f0cabf704d10c00d05182e534b23bd25b12b1efe9df367794e9b6e5d48337d48bc6d" },
                { "sr", "9ad19d3a6e995ac17b4644c723f597b5d3e53769090e51905f3c02fb4d0e8895ec2d51a33d49ef5c8da001cfa312e053755e172d1f01c80f591ccddfecee36a5" },
                { "sv-SE", "665dc2d6f4c9cf4cda0abce6828ac0f6da1c15fb7a3c707258d69292a60b560642c873c6e9d906339827950697f7e0c5e83c268a5b0f8fa541d24d4f1529d197" },
                { "th", "10cac076f6146c29c3cb3e7d93d72183572dc2af642ba01ba6505f93270720b09a920be781fdd5340e91f32933888175a9a3196e54cf204dd7ce961a687c5bd9" },
                { "tr", "1bcb4b7ce4457b781299e98ce5b10be98ac04258241be2ebb9fe225e08f8a27ac43a3212d0ebf8ad85dd3350697c1c79134d4e585b4671275b61a227ea1afbaf" },
                { "uk", "7d3ec32e67fcd28467c1585d443e6fb58893f9e31e5203034b88812fcb60accdb22579547dbc15c29abed8354ff90d3c932e4c411567fbdb0fa904800f3f7173" },
                { "uz", "8bbbe59c81c57bfcf512652a4deb51be8a91f6377d168dee2994629af377be92939c4fc6bb36743004ad1d7226fddc3a4bc7aee42e1e41bbd456c3bd042dbf49" },
                { "vi", "0ba61a3848a9e66d87f28362e90ede6661e3e8bb98e65869a5778bc46baa0bb1d02b5812a2f284bedb470c882bb497412b4207bfb2a87f16b486bfcd157ba158" },
                { "zh-CN", "bd91dfec098e33cf47aefb9bd08b0a775d3a4184c47b137f6ea877a3ebf283804c43fab715073cb21b329c63c98e36397085ef190bd0e695264559f3c37d7ba2" },
                { "zh-TW", "0598c9ce0ea4c610885c602b623ba25837cbb22f841978826ae0b564242f66165b28b58da679c2170b3b22865e250773a2191920e50148d3611d9d6da8bb7a09" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.4.1/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "734244aa1f7bb19954b1063f6061c96ce512a7ee0c672978db8180bcfe6b323f7cfae464c641f473f63b2cb1627846882c3403b0635dbbd6a0624eba42e00c49" },
                { "ar", "ec3ec328b51ccaf544eda44240465c9b481a244af1806e70771655894f1d63975ebd6401ed1b105b47977245648a0cb55920e44f021345d65e87207cb195cb6a" },
                { "ast", "bc7ffb9dd51c4fcae0b6773eadfa63ab77e9ae47c0b5c1a68e44a737f333c9763d0afb39e2e95c07d27ae77417016b555ee196a13d818341d3665adf287b3f7e" },
                { "be", "ca339d398ba78d7ce458b7ad3cc568e7d91e4d0069e28053cadb196b44e60be15f6bbada809305a374ce0e3a0a87efaed2d2c9fd696a71e8c51a933e26da8b68" },
                { "bg", "58a644c64e1ab125a4021bf47818b41bd573d4fa1ed569b7ec33df50f6d9ad727cc00e09aa4672f464db3ecb491629a889f83a5a0d024856d9fbd2064f74db60" },
                { "br", "0283a13756938e92dd658ef03d430850a8324f602141ef354bc503f5818a0cfa24f4b541dedeb3e278fc5dd192bf494c8072531a782af4d9ebd2431d55f3ce8c" },
                { "ca", "3205f57b01838d2d7d8cb6829897a7d95dfede405532cfe849867355be196b83a9c792ce3631335fb7f0ee8114d4ba7d1c992ef83afd5b44d8a7f0ef5303ed72" },
                { "cak", "8c515ed2bef6426ecad39873ceb72573c4c69fbb71d9be09217d4cfb72433b6a08db2ed1cd9bfd58351fcc1c8112c94a0546c333bafb9efe31e86ed7cab2a6b9" },
                { "cs", "5c53ce2c46d28ac037a68d85c846668f444e4c878500d5ae26bf2119d7be5fad26a527d8dc18f37078094843d6271d274eb64a79a463ae98aa25c91519fc0f96" },
                { "cy", "d2642eaff165901679f7310126e6d74c2a27b37095e16251ac6f617dc0509eab3d28a727e16e5465bdb9cdee76372a9e3f176951f6aa8abc9225676bb9082c27" },
                { "da", "8cc9fbfe93e93feb0e3cdd4bff10d7d87140d12add848d0c8f4a69753b687bb8d0961a0fc2244f79be707eaa382a3565016ccc370119ae005ccc7e11170976c4" },
                { "de", "27ab85ae1a4bc6fc8840e82205324b51ab430b6794f6c4a23aff999c6ddde7c289f59ede176e8b334f16498f3ea9f121a614e2aadd76848ebcdd5a51d400a945" },
                { "dsb", "142a4955b1edbaa6e6db18f30e545cee353759aa871624816c44b36218038f530f3a614e16e7a54aea6ea7734dcd6b2beb9588971e25b8770b74c3c06eaea721" },
                { "el", "4226a0e77139fb734d0096567e8c19c591fe219a73ce4dbd59482aadfa0f13068a9440dbfe4d918dcf6371d55bc678cbd3ec0ac016d6bc7584d3d9bab072c6dd" },
                { "en-CA", "ea615ea3ae6507c78bca89a8baa26a21d8a5b827f03ec0bcdd1c2ba9eef53e70ff9d36f0e808ea627c7fa342dfa3798e0020098f1f9400b9f4e6017c13dfdeaf" },
                { "en-GB", "4819b4c53a840ca4195bf566359aea806c3a83ae0b0c842f98d079ea584f60cb8e6d3d2f121a8225634403625d980d2657de7dc7011ddcc7e51cd89c6c6c46ad" },
                { "en-US", "d43ec3e3901f10378b11353e5cc7df126f9854889668a9ab3d6ef947c916c6d5be2476d628e45add9a42c50c77dc9d668966f5544882e818fd7ca1fc3fb17e76" },
                { "es-AR", "9e53d88e239b24c44aafa9785b9dc22d5fb43dc928b2755e26c4979605a6358e5d262c3ad9a6bec601caa20b7f10ef53cbc640bccc049523a18d169113a12d94" },
                { "es-ES", "546ef338aed97f1e1a86d45a53f0fb573a11f50795d0a041b941202e173a8955a92b4a3de10ddf371b0254f961366ad5b8e93b623620c8389fd42fa90389df23" },
                { "es-MX", "c6818cd8f4c6e018621fd954fbf2cd0c001c82f603b2ebf984445eb5a3c49a38262687990f3d0467c33cea8adf72b49aeb53cd1fee2e398cd80eadd23154fdd3" },
                { "et", "9604f4782b0e294e8bd27ffae99761b28a7b369deb1be0f7e9b7208193b98754fa9951252c44388fa06a3b65b605ff7cb6ad002be2f37d3b954160dcfdddbc64" },
                { "eu", "d18ab6b55fffaf9253ffb29c6dd6411a1a071aaabb424c8605c045aa06a8fff123324114944448e7490b8c48a9beb2b3e872e43b7795a2974b15caadd938c1d2" },
                { "fi", "2aec37f04d1c3db0b18dc546f2d2aa8a2606cdbfdbbdc798bf0ea1177b7aef5c47bd9ab8bcdd8f2b10dd0db32bf51690746eff56e1aa13cfc2b7b7b694b30eee" },
                { "fr", "79c02f626805c85fc0944233ad9dab843910cbb2c99f3abd3b8e4898fcc4e8555d4e8eeade7e8636f9342cab66c5bea2a6c002627730d1f1c85184437c2b237a" },
                { "fy-NL", "52ca9e6784889ed10e111fb86291471a0cf90379e3d5120db6139988e4e85dab6a307f96f6e8a1e64feebac73e9d5a8059ddfd65517e32bc50d33d0263e7abc7" },
                { "ga-IE", "0708c8ca78fa1362e832c275c23de92f4152113c297c25f96dc0f2980db737c839f9a8fb6853081339c242a46841041ffd8ff34d79ad55f9d673d2995abcf59b" },
                { "gd", "bebb1e5271bcb47ff3587a5423a5fc51d1bc95af1421fab0f0dc288bba7cf7c4c05a5d1c2b971fa439e4ef1445954bdd457e1c850994ca4d6cc7dd2337db0560" },
                { "gl", "4c1e6ff23cbf25adbb2377a8a8b82b3c245312f187f1d42e9a5c3b0bb2476c17bb7fba0e68aa41dcccd09bb72a6ae0e03dd0fd3bc77359eb4987129bf98d1880" },
                { "he", "8871d0541037db1dbd8e37d0433822748e3d38a2d9cfc4a4bda3c74d2bd1eca42b84e29c2a7ec89de1a9336792c8518987b0880477002525632ba3dc352e747c" },
                { "hr", "e6b08c1a4407f8bf6f6001d7e51c51c937b874f85696cec1f597ca095b912576547e1a7ac962584d316ecbd325b167ba7488afcab68edbc2e07002efd3a3d9ad" },
                { "hsb", "67857c150694311efe58bdab416b3f4b07ce8a3e7849292ded559f3e3e8dfaf0f44cfcfda43b30b2297d64ce5988c541abac311d1144a2bfa6e4de9df0072c0b" },
                { "hu", "5064e7a3a583675467478c0232179781fc58336acb93086b8693202f1e5c139951d2a04e03e738613ad79b8592aa8d22cb9ad9186049adc2b7937c5e260475d2" },
                { "hy-AM", "cfc6f0415a991833d63a871a207d0f411962e02f6ff3ff33f7bc5fbfa7aa5357ce6bd13e9c2335bc073705a0080b3b12cd5aaadb11d78526bd580af6cc1ce1be" },
                { "id", "83f73b65b559e6950cbf7830b92404a63a7446a83d123bb8f3dbd627ffaaacadb4d4d4e1b399983d06c6f034c5601b07c62d07836b4564c000e2dd37e177d5d9" },
                { "is", "341d24894e97840571d39f9536055dc84f9829347ada9a01ac765764691144339bfde64109759b38c1c6ff43d8093198f2660f45146047094edf44ed784ac794" },
                { "it", "c448f210b11dba281f8085ab611de3cef4ec836791377a62de6ff6c661721172c0af86632d06bf922becda00ec471f1c6a77f4bcebe5555ee7cd2a7aafe83174" },
                { "ja", "f406f684e30d14e719ad6ace6c0416c265bbbc31c83713e54aee6cac9508622717aaa334e066b44b6017a749dd698bc6b51cefa436ce46f59c49f9dc541479a2" },
                { "ka", "cf3261d6315ba27236b1cf5289e47735f0d3f9ac228284df56222108304b3821e7863543a8f1c4f873fbda3583c31fb6b3b733f0b7bfda26f91031d64d7a5e53" },
                { "kab", "683fe0de79c05a92afee4efd42cb47341cc8e1bdcc365a1f77ba6b12f2b2f62eed03cee0df6292cec2a9de47400e494a7483996eee5ea2eb1f813bdf40910fc1" },
                { "kk", "6ff5a8a6644f8d4e3c70427479eed7f3d9bdcfe724dfcd5be53de393982202e68da92e542cff8b12dad4dbaa2a17d9d85acfb0f80975d593693e10d32782fb1e" },
                { "ko", "32e603305f3aaa814423088e2ee7128dc902757cc610724a4e6c3b57c188ed3a78bc1cff8081293c2c606a1d8e4e895d8958c373000c755fd522d37a9b161851" },
                { "lt", "6cb92048ee156db57c7846f3713e66e0b0752afddf7daf8242fea50613125b05e9784ec6ac9d45e98bd87a598805c65e502ac2aa70f62c5e0bad6ad2c1e4fb72" },
                { "lv", "804b0e5b42455285451d0c1021f2b588e532b110c6b17ed0f9bbcbbd2fdb0eebe9f80b35e15565f85461e8ce0f0157497f4b90d7c174e0a56eaf60a5b33ad0ed" },
                { "ms", "a10c6227f7d313c9c9dd5e7a33f1d864a5b0909537b5f4617ade48d096c3a4d794b3faa1a3e30e3138f1374fa9e311e3614d56f1dc6188e33f5a2bfb3c956347" },
                { "nb-NO", "0b2df7d0398e482ff2eccec951ec390f679f1662ab2f69d00af8a66967f424101172d4012d32ca973aa8ac1499c427dc24a0173dc3686017f90c948e2b3f5b22" },
                { "nl", "dcbcd05b578b970095ce7775931fc13e531dc7c003e10420811d7c07af160dd620bcc4056c935cc8d799faf064af675ceb928ab4409a36675f4322a8f5e7e7c6" },
                { "nn-NO", "e5d8b5566b5accedee0f11b3d56e0e2bd83033ae44e3075bd9344821894d2c3200709a99e2f2a20cce975c400c8456995ca89a955a15a219f5527e696574c70a" },
                { "pa-IN", "8be82779ed7b87d15f3654a1c75ed60eae458534c1286fcd5442ae576c088c9582b31a18e31a5595d9b66f740275356ff056b4ae3b6250d60b134ee919718cef" },
                { "pl", "9aa15a5965f43126d149f99dc45c454e08ef879931dee6b6fd944c5a8c7a03deae6032425ac62a3dc15579c660bb97a11337b79cb34a66711d389b0157319953" },
                { "pt-BR", "3516aa209a01d6dcf5c935f222b6435b050054e7e2fc16ba5fc9719f4f9474d51b4f4d7dcb9a0f49fb3233b2a533578ba22e0d06f4e48c41444cb3a89f1a3800" },
                { "pt-PT", "129da63d58e45a5a7a4e985d0f53e3bb46b9d8f5c4f08aa555b915fa85a6315bb48e31bb04e86dbb5424d33e462fa4b577cff8074497daa3fd57962629f573f7" },
                { "rm", "862c530d0a4edf06b56ea881dd9bd5ca4e8e15eb1bea5dbe80e5839737142b13889322a9249dc86e938adde0e68281c163a6bea92dd1aa98a9f7364899060870" },
                { "ro", "4e83dcc1e4a989bf2a0222bad9353acde625b0af4be38d38358d5f45f4ebfbd3fbedf5d6cec1a6c571362f215cae9eddb45c1a6d1bd92eebfedd730587821180" },
                { "ru", "3cca7dd223e9ed96df91c4c4292c537c936a638b27976da4c692eb3ebedfb28ea316810bc6be2662a9c794810c6adb3d17c7cd45d9443ba70884b45020a290b2" },
                { "sk", "1163973a53cdcbe8f78ca8f857274311847b74f9c322e71f20312b2f5c9c8e1db24e8dc3b0ab024fb0d3238d13d60dfa1b38f5c87cf870d12dc6e250e9924280" },
                { "sl", "0741fb6c1ab2a438575cfb268268130794065df610252f0fda818a039e091a2c4a57e26951d6955762aa46ea8bbc2b32a9603d7e7250fe52559aed3e65cfc2a8" },
                { "sq", "9de866f4a95797d8071c09afbc330e44aee7391e5a05af3c342bbca8a01f3cefdfdcb34b5443c4e9f0a806b466b1d99d841c92285decf44013ca4a7666db5366" },
                { "sr", "3d4fc52d4e21fca563261d5a8467330defb86cc711da001ded8550f231d9a654875f6e6fe96f01164ab6454360d45ff3ef8e2ce4f947a0d03335c181b76bc99c" },
                { "sv-SE", "c3729905a82b72ca2dd3d95b8c58a358ecccbb5e5de359702ec0c53952613b67896ccef8654433c7326f6afe870785db0bf3414fa4835617d3fc082e8ad82d1c" },
                { "th", "65f2974bc0372c6c680f17f7c822001eec1aed5e6459548d45abc5a1e670e5f606682f2fc9aec68333dbd656691802c4bcba8fec0779ca02f673ff173d768063" },
                { "tr", "71d360a7fafb57ad95150c415f37350f6bb16ccf4f9f93e7ef1575f2c6d4e809a1a3eaeabf5d57c71bdec30f058395482c07770de8508979ff1c4f7ff7724fd3" },
                { "uk", "35d67e05d81b8239669e2ec0ad9e31faddb643c9141af25dd4b11a0a068a269b09d9bffca5020ca491b6924a0535acbdf1a40c2036d173b22664e3274cc8f6fd" },
                { "uz", "35d16052f17cda13f81115062b7f5bb10baa9cd2079c663cae8a3fd8979be4de04352b9bca06af6f07dedca22f37b2e915f02f35d5c90d04d2768266ed3a5498" },
                { "vi", "b37984ddaa1dcb0407e188e3434375c28c07f135d3b373c7f2ca8b658a0cc7b55733e927e919215969e1e77be36306b18e2bab0c069402fa26d49b41a049b1ef" },
                { "zh-CN", "0038d4559df761d406cd02063bd492761c5290d2fb25e738f8b369aa039b928413ab80a2115abfaff98d38530d09a84e0493c285f42d5aaf6294c0738b857597" },
                { "zh-TW", "f9c1cb2a17cc3b210031908b4899fefe25a867df3dbf8f0e597e8a071a045a8221d5d1011bfc2611f342d6a66cc8fb1cebaee74b0665be2ebeff5c0e07c58a2e" }
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
            const string version = "102.4.1";
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
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
