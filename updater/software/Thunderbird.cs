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
        private const string knownVersion = "140.11.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.11.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "291c39e09536426a2ad5061469d4f20e7a72d7f4418909dff46b7057800eeb16ae5f32ccf3b081d735d3f99f4c3999c29130f6cdbdc2cf42d6b7618936dc5359" },
                { "ar", "e9bcf5037b97195936c8744434307d881512e5aae4f1d1339d8b0ac36f82ce92ceeebacc465e700eb4e7d94d9592c308ad6e4b1bc2c244b34e941945e0454bf4" },
                { "ast", "0b79b45cd0fca8a5df92410a6ab74df9b12143b77195b6dbbfd5ac6387f5dec43cabfab2f7747490f2d57ae7ae13d530060bace80ba47745606496f64e29cdd2" },
                { "be", "d34d2807c9b3f4e01d4f567391578363082d3a75c60b570b8da3aad32c970b6069cecac7e78d116e9e1864bd7f6837fa94726795b9d24856dd5b079cc7de9592" },
                { "bg", "96629bdfb169710a4434ce2b3a0f9735676e83850fd3818123f297d29e8fb60d8ef70f47ad2fd20869fcf24ee3cf1b8b9b5f244a9d5d670eb9a52c2095976766" },
                { "br", "b7bacd40226855d417587aa506c35b9304434fbd218876719955e9291a95fa094d9968e6734ec30799959dab7da854aad173933a832babcbd21ee49b0ef5e2b7" },
                { "ca", "cf89658ea7497c5923fa4fe7842179f385b8d608fc0acb709e33f790a14d8a90069d41cc286a3ab0b86eb3a3ee7ea091f69cf94fa0480840d416e31e8ff702f9" },
                { "cak", "a18bc25eaddcdcb36f28d47592088cf5fdf694d4c5f9cbc75be122e13e1e08186d12fbbebd27ac04feef862e9f401e943ebad91216efa52171b16204380f554f" },
                { "cs", "dfca9276415c6d67ce4eada361d52e6a9e8e7e4bdad688feef0e397dd3602ce5393ab90ea315e5460fc9579f899a2a98f8ae7c1f13a0d41148386e8c58d9bd79" },
                { "cy", "ffdb24ebd73e4424a8181f97f2ea081d091796209017867a05fcfdc3fec345d0b09234b34058772b4bc6aed0c7c6a02d49bbfd3d4f2516ea40b9a5de95386a31" },
                { "da", "afabd3f81b20a398118556bf877fd20c661d4c660fff81a1534c64f2d425d1f102d74c672a63c7482e84975175b7ecd866320ca853994117a12a36584175e871" },
                { "de", "54acd20cbc417648309c74f982bc801a550fc840d4720605833e21237562efbe20aa50c8854b15d611385ca1d75247f84c9388419ed167663f6e8416be041966" },
                { "dsb", "52c55eee65eb24c6f918543277f17160ac86f37e0761dc51bf521e5311cd4a91a25a7485467f24c2d569c17181026fe781a7d1a720aed87c362d6d0faae3e59e" },
                { "el", "a8fd25f62e572c77d3fba5eae61d974034da1b6d2415e11b754ac7e69b20f36bbb04bafcce64d82be7e85274eeea9750e655a9c09e54f61b058bb2d1d268c5cb" },
                { "en-CA", "eb122e186e4f149423a45cc3b801dbfc689c557df0d381da51cb94c050f21a922ed7eb13dd76b87c28701c004d72c438fad22a2682551f7d8c084af7bcd72690" },
                { "en-GB", "e4d89e0c618f5a3baa0772e0f32e271ba6cd1320deb4f97dada30c56e56b2de986690f4f9d430badb6831f48c064c41f565ff7e0b8574fd46c4b5f74e7b5e62a" },
                { "en-US", "6925c33b0dd668ba933cf24cbf3e256dfbf2489da00d80114babf48be4ec577a5825fa8fac6e6d9a15ee355c5d920af08ebeb2837098ec73b2a949597b4ef9ca" },
                { "es-AR", "20c04d5409350714e9e4ef01de4d7fb6d54aabee1e3e692070a0c4a0823c44577392d24ef245a3aeabc63a07d6f786a7f2daa4cf67bfc8e94bea1e75e3a794de" },
                { "es-ES", "957ad2b01ea38cc1943b34853bdedbbe34f1a77872bc95f30adee4c0771b61d4ea22d08391e9160e6bb28eda9933cf85972e857f065b3951e8244a9addb95de6" },
                { "es-MX", "2da161e794cecf84e43fd0851a794171b617376febd1cb68eaecdcc8db7ab60f9b7b02e781e89d63aa72edbac657de97923f305544f6331ef7b7bffa432a8b6b" },
                { "et", "e7969df9fea7d89cc4e15fb5f8927d192389b5f09c3b80dd3efe315c18603c8d99879dce851b7366987c9aaef0acb1f773925105449a7d96f231a06c5b949279" },
                { "eu", "e8ed5cc71bb58b13bec8f0fb972a20bd43918f0a16a4e4d91c5cac836fcb688de71199ff7819f44618204e575ca11c80c9d269e96b40cb7faba8ef666cc80784" },
                { "fi", "06968d001497220c95cf33716d7ba895849abceadbf90ad32e7a944ff10810659d67e9582ff30dcaa3de91a5e03e6406056680a1c6bc4333d72669095997d9b9" },
                { "fr", "3de0f27a289ae77fa5b1f2c0f2bb0d20fc8eed0a5a9db99442d311c357c10f185a5a2ce65d0b87e4d725fe4464b06dec618e2705e06ee0387c3a14cee0deef74" },
                { "fy-NL", "f8845f38eb6c18ed9441960fdfa7825f8dc1d0026daa86678daa7a6bf1065587521d0dbbfe64cfc36a07c1fd1b47c8a4b1a7ef05ca57a033eeb28cf3fbf86579" },
                { "ga-IE", "7b850ee216a8dddb87ab3a0ee439c132e4254780e33c78d353076158416c8c68dbc1b8418d92ef6e1413a3912b0c04f12dcaa53c600235cfbd0968d77b5966e8" },
                { "gd", "5163fda85145a2c71b712524596eefc80578b3aa31e83409e8b8b3cae4107351c4c461c565c93246f55bb238dbbf8d1dbeabe396892b4dc3e724d92e1ec4f61a" },
                { "gl", "dbd61d95c75a864f053d10e0bbec53ed1404f7b9137ba1f7754f9d97fd69cfcf78a5c778e27b68cad9865ef894ee745dd0c5445606e7f082bb1cc26df5946a49" },
                { "he", "f53d41a24cf347dbb6bb28974573a0e7ce64e2a645af4460728960822420a38f2ce4c2a4d6d00849b1eaee1365563041fd1ceca42baa6eca81c7b666c8d1df8a" },
                { "hr", "b12b830b9035ae5efe037a74a6ddbc69cff418b9e61209a5da81f357b575cea028ddbd04e5f75033ee1d9d71381cd73628aea915dd928e849c16e1de37b2dac4" },
                { "hsb", "22fea0ac155372e1621eaaadf4dea6a6f3c52d38b5c29479a1c4dfa82c3fc6e572a6d04580d4debc1e943f7344b43bbccf6657040c85b1e23c98033aed047440" },
                { "hu", "a16bcbde532e6d40f6c7d802d97d5fa963ca565362799e92a5ec510caeec03a15f261de61dbd7ef2c3431ccf13488acd4885779686ecfbcfbce999a07e4a4e42" },
                { "hy-AM", "9982ff5697ca7bc6e1f04742078945dae6439844c959943c6600ee9b89c1b2ad219a016d2e9dd8830494c150371b573b5f3f176047e7ab49ed13dbee41c68d4b" },
                { "id", "d7f62b525e015b75879754abc9e5940102e87b131416e22ef62ff7ea69c62666c00f8827e2a9df037d52d40bc0e4b2464388e70ddf602779f1c8ce0dfb714c77" },
                { "is", "e08e037f049efb8c7958eb27a824ef4e77a02a05db7dcf1657cefce316a540557813ea8bee8c76c1d1ebfb36cd6d19410f4371cc26812d37ad3e06901d328edd" },
                { "it", "80c38ce5debbb18ccc403f31b398c7dc9eb70a32ca14a4a195fc7f065c6b89ccfe7621d4a0daf077122ef03e954559aaf408eb5a456b4df0e8347afa051919c1" },
                { "ja", "3ae96cec476b8b148267c7a156e54d5524e453082cfc421e711029f21afaa8471d3c9686a80f1af98726423761d2002db3e9068dbb5cb0dc795ab2200723c7f1" },
                { "ka", "a8605e1dbc9efc00e9fa77050c6367d8e1a2e12517e0bab0d1c593cd94ae9273456a1be6c26ce847b76c1ce7c1b68736abed6f96664e5abe5d87b2e255511713" },
                { "kab", "65e00e152ee13661f5b6c600a55a2324680b783ef0e7d4fe28935deaabfda909d39dc8244e00d1957e6a2607e42741cbd0a82633db3029030dad041f4c0d87b7" },
                { "kk", "e18d03b0dac98570c44c2149ebd0207b202608ca786c4a71bc7857dc77e24a4f03ab95a54817608c23f4a22d4f1dcf8c8a1e31d0d1887dd1c93df5aa5cb56ccd" },
                { "ko", "ad6b9467f0407e6800c5d88f7fdd345ea22cb15f93e6704e43a9c3b20a4cb2f986a52c51dc2f677c17348fc1f1de6587d346d14638d94d0e28f10cdd92177841" },
                { "lt", "5e7565e2be903e993c3641379e9cd0e442c198ae6e5c6657b7a03a24fa1ec760b66fc99163334626ebf00ffc75698b2517ccf8f41b5277422a98c2efdc623756" },
                { "lv", "e22f1d7b2c220a41b8e5eeaf186fd01e9e1709aaa22e85f7161aa58aceaec62f09a6a64a7db06f309f69c472736ea3a8db0c1007f4ade626daddb140635881f8" },
                { "ms", "8d27f423fa828ef80f2de7b0bf78a7e3a8bc7588173b5aad5ecffa5b238743235311ef206c1380ffee7f61a5122f9ef95fc6323e8c9b3944c59d4355316c1ddb" },
                { "nb-NO", "a3029d19cf564f3ab930cf8a02eee93c4cff7016d3fbf1b80b0d356e0b4b0ba7046a4179e0eedd8b9d56076cda4d88d100a05880ff5e1489bf1d1c96e894f8eb" },
                { "nl", "1bcb4dddd210a8865fc9feb42405ead7eae986c8ce790081eb57b820ec1ff6acb826745e40231052bea1aa9fffe3c3de6723574b14d00af0659fddfbad8648ad" },
                { "nn-NO", "d21e0fb97ed6c67c8281f2e0d4df121e1da4b35a20252012e89224a34fca9b5dfc4d317ba602a1631e95262c95e8f9bc5bd10eb1c22263503f1731eb72be9e6f" },
                { "pa-IN", "1c4d3373e7a143b014479d87ca06b6fde27d9ab286a9d9c1d5303c4479ba8c0dfb210c7c4dc48e4266880560e8475d9528e8aa8be08ca0388ea16b898594684a" },
                { "pl", "f0323d8bc25e20fc86d00503938e49442bbb86c413e2bd16023b4ce3ce190ba4868f54121a802a64ec4c148d9331619854170455b1640ce875e931c6004f4eac" },
                { "pt-BR", "c2083516e2d356697d8d0b33dc7d27c7c1df4bf23ca7ecd5f3109f37d5c379af2b9874560490d50b020a3424654e415e64a1ba82b7efd40554d59d6ac91fd261" },
                { "pt-PT", "4c3da9deb4b144c3f124001ea940c4b3179e1c825110817d16debacc539db8a1433beddc3ebd87141f7b48d76123c6ce6ace74ec4195c260ab114b226a8e3ef8" },
                { "rm", "41cc12ceb68a82b969ada02a324988316f82296b55358e778faa368553149da297b9fb0e6a541dd3729619be7419ff9319ace7f2dad0eaf917fe8e0affb2eb31" },
                { "ro", "78c94b57758416e9fbc893f34fb1f01f4147cb89eb88da06fb20d198e0a9d86705e4744a5b595afed2fcc189054c3873406cc9c33f07a9f2762409a040791fc9" },
                { "ru", "30f1cb16032d77e7371dac676d3dd12239aa48420f9969fe4c1b5a5e14e03dc4a602ca6a627fc378a40031aa80a58acabb4ce0f65ec245e5190ac73e0be3a5cf" },
                { "sk", "49c9149218192bef2fa100711770e66fd2ce13ca13206661fa8bf0ad95b5051a5eccddbae5005e5fea5ab538f3661e01537ca670065d8d32363e762c6e2f5c47" },
                { "sl", "b079f8a3f2ed31af397ae968c94d8bc53f9e6fe42d7ee329f30079b10eee02b8470f200180479a13cc1d30f52fac8bf26b5142a7e1b22aa99d763802d7f9a787" },
                { "sq", "ca806010f59c90273fb60849459c7d08cf20f12f6700c5a645f008cedc8fb32ebae07b8776b955386aaf1a979c00eced8a767fdb2b801f2ee0ea23ae526d7c69" },
                { "sr", "47bcdb593684cebcc46b136f7105833fcbd146315dc73d01e50f0288090092c744241610d005f659fabc8e7d313073b675e5334011f155f977f10fdb1a2e636c" },
                { "sv-SE", "bb4ba9e2e4f9c119a44500dfa495ec42afe045c62cf3c23f69402d0196bbae6aaf0483db274b5f3e7b9ae5c8a7ba4b1ed3bcc5319b6855e5617829045fe82546" },
                { "th", "d22bbdfb1269c40dcddc88d93247ee14fa2a64634d7a06bdd5f98cf88e553c38ec777131c4ebe87cbc4501070bb9cf6170964395e5e5ddd47ab0a19f262657db" },
                { "tr", "9e8e1007b2e23c0c55b646e20be7c70f7dd6c48e0c700acfff2c27b5f8b38ec25541c5359ab597aaa07e7522541c0011379f7aef81b87b2f7ec8c7048cdab349" },
                { "uk", "cf2fd8f8cb36835d1b6859c2b7161a8916667c26b6b46a7864efb6a52de831ce2ba85c9b8c6354c057c84543960ccea6dc2e3491096f8dab47831199da1651bf" },
                { "uz", "0246173a887b84c0ec2bd29a8c352fd19240298d5b1013a2c7d80ebfde706b56b23551938929fdaa759424a122732c215c92bb1a3ba87e3211058461dca0c189" },
                { "vi", "2dba3abb3e7e573ffe41341876dec70e38174ca279a37c2456e692dd414431885db324e380f849ebd216ba3ddbd821ea94e57b9b729b02d4fd746539aa4655fd" },
                { "zh-CN", "5e4d79ebf8404a4f1aa083b74c06d90a28bf198ada8d32bda5fa90f8768ccabf46b860212d0e62ea4e1e6d2e2fd607cb828dd83c3c4d5b469f7a7a02c4b932bd" },
                { "zh-TW", "7d793c49723c5db0eda5092d17d192e948be7461a668d2573cc07e14a11c31a30e6c8af7996225f17c8e759900c47dbfc8aa75b84817832eeb49e7f23afb1264" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.11.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "dd3703a95e4fd54c98cdf2b145b0fe991ed7fdb538cfa085b3c3d4fa52d87e10cb355193efb4d5bc1736b155650d80044df317e8424de24a10adf9105a3bd9fb" },
                { "ar", "8031b4f2e078d3b846b290ab5368202b41fcfc719b26a15ea72e32217e7c5dccb35be73d33c45d049035306c2e78b3c39568fd05eb8223d525396eee5da41594" },
                { "ast", "937bda7e7ae3d75e67d2adc4536a2a529b5fe4289d53cd7efcf19b5d0488a047e055c20a894bbbd8d504e8a57cc308632eae80f410e74bc8eba18fa5acbbecfc" },
                { "be", "f363acd083c63f4efe953285c1b120a3138015d7c031ccab84e09139e0e86875a7823c8a142d0882e537e7db616fdc4e4d58b601a340a4683bcf308dad256a24" },
                { "bg", "1b12ebf357c217139ac44365a7ed5b851c7ccbbbcea2134c123243730ec1d69b5e7880a1184c5796422c7bb04cd319ddb6e186773ed09fb89b60f84f9de7469d" },
                { "br", "7f48320b53cfaf7a2ec70055c53d8d7492dc572367843c9739a185642be679e400abd25eb403f390202506cbe4ba5c15ff3e025692d1d085f7b909845464db91" },
                { "ca", "a004cb903db5d0f2115cff3cf51ee86b0d71f02e734e1bc31973866eecdb7025f80716a61e4d1d713800fd2db4a5309dfe282d31a8ceb03e53085c3e971673d6" },
                { "cak", "d6107276a441b434eeeeb17ee5d223b76165d39e19c3719b840716262a837498b84c52134dda25a8c68d5901b939898282de73da493f537d5eaec401d83ff3d3" },
                { "cs", "b68578b16eb01630677feeb6241e91bdcd0085bb02713aaff308877b414b7151a5fa2f4ee3f72fe98701f397777c4668bc8381d1ecfeb4778259c0d95e7a2a73" },
                { "cy", "dbdb110ae74ecf3fedabd15dad826c9c49be1849299ebfe86c7a2d51138d58fa933c96c5b5e110c9eec8e3922526b6d132e775105e15813d098661fa3b1d1a1c" },
                { "da", "4b75b59d16ac2143e494f71c78367f46de7b0923d714eb1349d83591ca086d36b08ac0c06d6c179014ebf124f7a5ca882cffc0603f9f7ed360cc66e5b21a3a68" },
                { "de", "e63b183d24b6dcef6e26ae0d468d94d7f2d5e9649008af43eee4e39f44eae2ef673e8c06108008c216a481ede5076edce49be4e61b95cd5423b6d6ee8d30b181" },
                { "dsb", "1bbd6d2664a5856f919c129284f226dca7d08ba01b2ffd02ed90ce6c06b04ed9779f2a3e0f7d101c95a670c27708588c0a437c0c13d306c496a7ac95d35e20d8" },
                { "el", "1ace4db36bd03302a7ae14381ad742ca953fbcd375d4a45d5129d4bfb183b065e156c1d392ebe0e9d8b1828decc63a91f28f1e7bc960c10c136b8787203946c6" },
                { "en-CA", "15336f06d2e04dc7de4c7ebd426b446ae497ca31c76d238173d1778a14addac34547b3599ff62255d90967043c22abbca366267191165adc22c1ae0d90719fac" },
                { "en-GB", "17f35b06535c8b62a98df3cff59af5417417373a20dbee823bc42800b4d519779521dd41d240074122678fbd98db70ecd97670b9d677cb024756466453a6cd44" },
                { "en-US", "0fb04f16ed41f9f16ab9322f13c6b02cd9371d18766445f0cdb232d9e51ab27cb121d1071697f7a89d24cc48b1376aa5839fb4817a3890de9976a82d612bc628" },
                { "es-AR", "3a34440d4ede21164426dbcb429ab55e93cca799a6d26e6bec45069cdddc5b50df69226b725c5bdbb9d358b78267f50429fb8ecf9d5982aadf4296b11510b149" },
                { "es-ES", "c8d5d35c6507a4b584e6037a206f8cd85123c0ec702500206560f198fce7a3a7221eddbc4a9c26388498f5465f0978d73470fac66151b7455ff4d9d0353ad870" },
                { "es-MX", "879a64d4f8587da233c9207248915710cb5226c2d7710d3663127a1a290a393fa392d155286943fcd4aae0ca14cc84fea37d0668fb4e3783b08eaa6a85be847c" },
                { "et", "cef3e0c48b10298721a23a98510fde12e1d90f8758aa19f63d5383b0e2c379762030b2595b356c4df3d0bef8eb84fbbe5b21e9f8e9ffb84e639f37fb93a2f175" },
                { "eu", "63bc0857ded46c60dc05dd539fbc9d87d27163ab22bec4c5e11e50a2a49f23d20bd4c4ac64fc60aca61d57754533b36e0002ef983f27f601e441878b7d64d533" },
                { "fi", "52219eadd44eced4adcf7a8d0a2262f6258c45c4212567de9c38984f1624de6624b1f9ad661cf7708e17e406544efd2846b21863b059c5fb58ef65febc625d8a" },
                { "fr", "1d79d5ea15f80e10dde8fbd4bbd6e56602c66c7d96333d78fecdcd45a7d3ebcdb131b7c7a2f2f850a2972061c032195b3f7552da9565456119b101e4141faa3f" },
                { "fy-NL", "cc308ef975b82a66fd2fd609dac96a1986b35369d116b149471357096750613b75f1ac75ce9c8a32f2d11aabd510a681685bc31239dc459ca70922a3ddfd2835" },
                { "ga-IE", "44771b3ad1595e6b1b5ff874b20bd86b97573d77e5c76cfb6d5ddd1c04795f5fb6eeb54efaa49bd20ab6ebc73ef431617f51630da4da0a5998ee529e6af6d2b5" },
                { "gd", "7b778f9078b07f02fbe5cdd1e939ecc345e74d37c03f2e83ca5406e3a7db39755ab093110aa0f9a9296ffaa2c7105cf993b4baf8bf286ec14a388b586e3cac3c" },
                { "gl", "88494bb72c8d64e98ab695b99cce40b0011e8858b81327b8fc402023a2da5435705c1392fcc0c603a054672b05df492bdf9b050207f8ea4a25a2a2419c909051" },
                { "he", "671afe2b701453c60deef80f6cdd6f9a37a16755edeac5db727971c9ee5d7a88398658b0ea4a176c4b7db73f89acb288411a668c825c62b5bfb1c7a0a0ec993f" },
                { "hr", "ef6d2741389d331196bde58a050c448e7e6e1e5ef22f7aea6b00a47dd6c74917487f39cee50b78c440528584b5edcb6dc5aae46f896e419b15e185cea57057a0" },
                { "hsb", "9d0129f1fe2a3b5b6eb55517876418f961cfa0951d3b83829ac6f1c21c0dabc53d7c56e013d85494bbd76c748314e8897fb1df5c99e906ec38f1f1fd69dbf3c7" },
                { "hu", "22b16f1e53a5f0f2e1cca1af20c59db99ed60b0a813309196b65343fadf4ae13e016bec4c209f32d41529516abd4705ea8bd60d0f316d6a8dad5ac4fd153e100" },
                { "hy-AM", "de8dd9fd32166b93394e942e8fc33906785773bee6f8403582dde250cf34771e77bd739cbaebae8645e0b0378346fd2f98a24691672590236b3b606fecf2a3ac" },
                { "id", "32a871342fbdb35aceedc79594f45c0fa69a152b03e1923b1b2bb42179d6c4e3b7fe565102536341c9a08819795063e54fe642b94c762f98787eabb745c39a57" },
                { "is", "f81fa386f2bb4694f5fc94736d095c96e31575bab4b1877a2032d6a3db0f67ed21cd0e7324947083cbeb9939f498204cb5525b335dbc1e92751f130e336b5717" },
                { "it", "9543c55540f97ebd62e374d2184d3596bc6cb447bea84a98c146c03059a22cd462046478fd4ff855d53daeb759fa8d06272d1dc666395399249e760e29bef022" },
                { "ja", "51273524843dd978630f94ebc3bec312b3881ff4527e859699d82dd268ad4c432db4bee59414e1c7b833a740baf2cc73b3c94e73e354ae2e4be3a5349069e7fb" },
                { "ka", "d26b30750c986683558266d148b81a173cb1e174f904e3b7b7f63c8231ff9530ef15480c97feaf8901d938722c828c4b6c2c2a0d5cafee78c39e03dd44a5ad91" },
                { "kab", "4f16e22e2585571c2f866304a9f6aee319e38ea7859201f6bf2c632f49d059a898b0bf940003c66d5b9cfa44aaa7fcd97d6e4e79b6804c1f930f20df9210ce23" },
                { "kk", "aeff988a763a627e2db1c8f466bc6ef639c097852b26a8ce284032eafc80d95f231d204f2995a37b74d586d7afd11ee31dbf999cbb1192011aec671ce54a4edb" },
                { "ko", "6edbd192b203545be0e332dce96d1aa1e906f5fe5050a37676b112e291d6a7eb5361a29035ba2ad4426c295fa3fe4745037080c485c61ed5991ad80fc4acb4ed" },
                { "lt", "491d687a50b01ddcbf579e3d685f7f0101041b3349d44b7a234d66303e0c012bbcc720797f2718544e31dbab9431b20c78b061635d66e41f016360f1d8debaf4" },
                { "lv", "3ff423a154040b20c66c6f898eb9c3ecbcb2989e37cb7e31b87c9807218519ed1a0fd3dd6a823f0221aa032ee33dd91859bf637046680afb7207f98b89d2e819" },
                { "ms", "643c481c777380cd4be674f37ed0da26f6e04e49d374026c67dda75f2274b9b3e0d12761b7c976dfa5009d6221c5b6296edc8e0bcfd794d2dec7607d5438091b" },
                { "nb-NO", "cff7fa9c6bb2d3152f9c095acbeca122b6001a70696fb982021851e12fc0c55170a47a32a65c629b31738b1fa4a6b3ab3608afa6a6cbb1cdfd1513cda2cd5b3e" },
                { "nl", "b2d825a03d40939fb16c5c7239438cc75d55d1e06fdb06913bc09bd5d8b917d757907e9365b0b2181193ccc2941828ac11db04639afddcbcf2893cd60734f6d8" },
                { "nn-NO", "ef997f515af7993b18eb0145c741f49361da0a836c783da88347f8c9930c22d8d8a26a124e2f3138c4f5065ba5ff9eac7fabd69948ef8f13b7eb3e03cde3027f" },
                { "pa-IN", "be65fc2d71af6de8c40d7824ced4a9d6e5ac6b5ac25be638a8cc337e832a5594301b0b317ef22c8de7c8fb2f10476486ace35160b45b108e9118663015f0c621" },
                { "pl", "05448ca3084c3956144b094aba871e028289a8ce83591fdb2d7912b7c8f672897448fdca33e0a2695317b43c308ed761678226344dd6c1be9b2ec00098f5f794" },
                { "pt-BR", "3f1cf56808e671744d5efa3864e52188d6078a5bef26675cba53c7fb310cef5f8f4b61140f585701d70bb77dabaafeb024028e9154e6ea03ab6ee90b4687838c" },
                { "pt-PT", "b43f7c8a632f4b276ceb9e773ca5b5adfca6e8eb6ef895b53ca808d4e69c279553821ff8f03a66f1243d4383a626c32f936b9b5ed126beffc702ac67759b55ee" },
                { "rm", "afbfa08a79253922efec8cb3031762e7e41e93c050ea615b5d5eb2d34049ae4a7baea6d51102420f969208c20d8b4b27075ccc540bc47daa62cb674567983213" },
                { "ro", "87df14c4746e67cec2a9426d49dfed78b1190c522fe87ded3c313f9cd2cc0581cafbad201842c73dd11e32d0866ebc030803414c87c4132938dee13baf4f417a" },
                { "ru", "7fd673f73c8edb8d83c9652f281c1f72640a6eeb2e746369da929f1f5ae25bb665461c1e9454fe1e46e57e95dbc43a9f53358c922b9141f97df4cee87d20dcfa" },
                { "sk", "5edd9a987c03f2bdc0d8fe0150c2c2b1b62ba02fdb34b78afec69f7a7a857c4fabbec2c9ef0456bad908aef9fc8ec570f9584d3919b53c6498026e22c73292a5" },
                { "sl", "c14d851e07edbecbe741ebd94cf6ef0c280caeae377e2fff0d66f64a292fc12389e2f0d16d5bbec61708b05b3cf3653d0f6392cc6ecf1adffd2d598065ad7ed9" },
                { "sq", "b225c55f98f24566d9120a4de72fd0f3eeedde7a3ce5dd3ba8929a96daa4b96772079c5906990706d605636611497672c8be84d4bdde818cad26c2f4bd8d98a7" },
                { "sr", "497fd7a464a3910ad1e271a5d8aa2c6680e806dd2f6ffd9c2a461a17486196522b68121cbece3e41abf8d98503e9c03cb8e31bccbeaa4fc4804a3ab0fb4e2960" },
                { "sv-SE", "bab9e410d77d5605a14c60efec925c25bc7f8d694995dcd4cb7c1d5bbf5a7bc882a1de1ddcf7fcd56d398a12928e3f8ea06b932410af946e7591237781fd282a" },
                { "th", "c4beefc753bae7bbbccfcf5772a9823b96f22b5478db09fef8772a1559144c26e5437bcf6168aed0669b9e175eb5509cfaa037ba14d984a47bdeb3c977626fac" },
                { "tr", "9e684e04615698feabdeb5f4338863b10daaee7c5e9097bc9b5042dd68a40f834a06da55d08cf9df2a21df4b8cb0eb7407a1921c8674c2d74435a32818a28523" },
                { "uk", "bd5bcb195d1b221e9d5e1ba78ed13d46b28d12790ce0e23e3c8a7967e0e071c1f45c87b6bf8328b6ddc734b781ad6d64e7d1dedaa71119f8e436e2d9d379f877" },
                { "uz", "ca9910bb25cb83e30f18f0561795659b998c3bc40a7be7e985ca0b5f1543af086eae88f7b6f5467f924f0fc4231944fdc37689d2ec5b585bf9f4d7ab4516a8a2" },
                { "vi", "3f7780c0f74e04e0e7bedbf5c5c993a7390f5875a48e0f5379caf2d3f2daf331fdb4b8e9145ad8b3aab7126d3a4fd10f341ab8098b8f546be1839824e68038d6" },
                { "zh-CN", "13591209f7ae2154bad2ea491db138cbce67760be2fe1e90310ae4f6da9942b9f3cb3de7c4968b2a11ea9c00997abf03a6bba5051fec6839d5d58caf1b933b3f" },
                { "zh-TW", "8f102c9a3f9a310f8e4a57f8a142d4f73ae3d99c7e38eb61a68aab547596fba970bf5087ef86e8084adc960208e24353cb1ce7ce0471d6ec744077ce0b671342" }
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
                string newLocation = response.Headers.Location?.ToString();
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
