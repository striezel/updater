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
        private const string currentVersion = "131.0b6";

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
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "922b17b098eddd6e72f954a746ca7d43261c357ca60f2ac68cb93b80c8fa72f4817d248b80484ddfd27a495d328f25ce39f11a8c464bf0c0e15de1cd0628b2ed" },
                { "af", "e611109905a7f8f6beeaa923398c53eba5f16e876268f641c780161ec827d397d9cb54d1f8c985823d199bfde313ce09a32baed3868cad5a78534e89f78dc0da" },
                { "an", "3c4c47aed89b98414deac54f25f1b9ccaca295c112493e2638f6958d32f96422a65a14d7f264253e34114199c52cdfc4710288387cca17bc30e0df1554e4ef5c" },
                { "ar", "c07f372eef9424c3c73f987f8532c54ef6cfdc14f3ff7cd2874367cf879c95fa71ab929e7ad9265f0e72aa05b8475633cc7bd3f9f8dd23565bab536461bd84d5" },
                { "ast", "61563c78216e30c1395a6710b32f6b9702c7dcf8beb854ee321b880294c464d80e155e3d9b639e437ec53429e39e96e10bdf36b1b7271dae8949f2e21b6c7d8a" },
                { "az", "0305086335627bf677ca1601c674e131f41a1c8b4ddfcf67040b812ebf01c802432ac31fd6067fe410b4c817e4146c33cc6cf66f995d6ea0d4d4609e86b57858" },
                { "be", "5da600133603a31a3a0d673fac1e596dd11b92f6e340c1fc6a1e18c76a2dee69691dffe633f20c9d2b0ba286d538d246e6634fc91fffcfc42f19bd911eef0e85" },
                { "bg", "0c79f443414d2f6c85ebabb09bd6ac2adefe8e7611f9faa41b2a2a2751478e9b083680ebb0438435d24ed47649459d553f151e744d0b7eb9fb386823ebe17fd4" },
                { "bn", "bd9ebef05f5188b4b884ed851db46b50d87e7fa7e19752cf0eb46b9e99093950898be66416230b7e7af9b4533de82d590ef444a636ae36e34fc4799dc018c0fc" },
                { "br", "7d3f326a7d1e7fd2ad9ec7af217414b0353f810b1bef74d37b1dea3e409dbe02ef8132780381cd0165c4bb3ff6d523f48328b5f37ba639de04d5c28d6874aa46" },
                { "bs", "860d50b9deaf307c89ed48c453dbe50bcd18670c5f42b17ebe11d4faf97db95ca1dafe732762ff9a7fa5aa9fa6ae63fba0bd516fd52dc8375635010fe9031b31" },
                { "ca", "e9440c836f9f6281c22ec797d618fd392afc6f6a5b6cadae7d0b0f446d2007067d850026befce5da35215a8eb04f9018bfee4b39ba5c1c3dd6537c9f5b13f363" },
                { "cak", "f2c7b56f40873ed750144791230fe84e3ce8efab02b3afbda5e53fb25f4e68fc80558ba3a2e3e5b67acf986b011776cb921132d22350190cfa8a3311708d73c1" },
                { "cs", "d9c0c0fda39aafbf81c18930fb210d62f7a0e1aafeb0231863933dc7a4cd042e97d5d408477c3b269c03ada3284a3953e514f810271ded58940c952c6b4d7b34" },
                { "cy", "c5883f745fc4f70c73677373b5e7d48d5f367da191c8174e294f727386899b2eec2387af8481f93c2d318f2a6dce4604f903558ba3da6073492bc446c540c5e1" },
                { "da", "820f6dc9dbd943fba4eb12bef296943273d2cf97961abf4c303a238a2fb7ea1b9931c3930cc0966fbf601140e38ec3b4dbd60d5bed3e061b61c0f2df560ca5ab" },
                { "de", "989c31e2f8cf5cb16df08cf7b6ad1b33d8a01de3c5dda4ee9c2a4c7b450b575f02c682da1342dd3578decc77d4217ec78896aa240083304ae96616c9efea307a" },
                { "dsb", "51d8f657d10fe60d3b15c845f3f20b6c29b4c4be3e2e1d38c9d8292fbe5e733c74425daf5f2e0a111ea2b06e7592ccc0d374586e6ed6b352dc641746176fa602" },
                { "el", "1545da745a07d588ba9dff370525a7167f36aad87e44272344f9268fac64ff5891948d9328746cafda7baab2e41f977ecd55f729506d304ddf2d984950fa6331" },
                { "en-CA", "49efd1692b5e9f083cbe7f1c0de1be8f6f9e3ab014e3b60bcd059b428ca271b89305824040b6ae29be2e4eb27240afd9128b921038c5d9cdbd902894a54e567e" },
                { "en-GB", "a0c03e070e031940566c496e9953733efd54948dbe84cabb721d5aeb90f9ef3ed82fbf690909463ab07e301c9cbc9417b410be11ab770707a7978d176bf14046" },
                { "en-US", "275ee8c6b865b710454ba769c1b921c39da53a9238ee3ccbe997c0117db372af7d7ffc0ef0960f2d7a01bde0b3141889b4f382f4816751216b3592e278f649b0" },
                { "eo", "3808bc00f23158a6d8fc144350512cf9d8d669eadc94f1feeea7eebb326bfae5cd94e82d7d8b2cb0db8f08d6c2d9583ae22170af6cf0acd0c715fe36fc13cc16" },
                { "es-AR", "346a6e893785cd74796437cb82d40bfe8c5f76f65bb80c3e4eabc1dddeb372b97561f54859054ef28ac5caf4bc8e7f05f661803cd187270f2fcaa956bda0f651" },
                { "es-CL", "4f30bf8c8899e140fdab967fa6b6ebed09e65b0d879ade491c87828d48a68ce4d5827b15d2c06a578e38f7ab8ef8804386b3ab70c1d4ff9fd842775f45b0165b" },
                { "es-ES", "4f09136760063d1cc7585b49b8ef1531708b47d6769f8a0b37e070bd7fdd535ca15ecdd40b1cf58fa2655f83fe92778ef9e294f300325eb44eeb0e71eb782c3a" },
                { "es-MX", "91ec720de13da07dd87bd24e86d9b3dbe2b1a3d4ed3c65356f2a998c691ca082b0cf3d950e5e139c65eaad5e7bd0f798bb8adccc70acefdd7a08d209e3cda4a5" },
                { "et", "83d168c29c17f16a2905cf1350db075053d76ab70de0541e731d63c4953bde6cdeb17ce6221acad71b119328beabc9d7af84d930470e17b48e7e2d2f6daf7838" },
                { "eu", "0cf3d412c8dddc43aeaa58c53ebfddd21e8228cfc242b542d41c619d62ca0425af71a5cbb95f845f64d3b6e1b75900c7d18160ea40ecc087f4d011d922eefef1" },
                { "fa", "706df6498320c6d32e3f9a814e879ca9c9920013834842e72e9cfa5ec9dbba77e02c5c118bf420f66bfbf2d19a2928029e1e563ff1c86bb5f62c80baf162ab50" },
                { "ff", "57e86173ed6abd6a715d78db9429756b0c86c8384fcf3f621902d59380c87189a390b91fa36c587917f631ac0596458600d4d6a37fed232dd7ddbd215ae9c6ce" },
                { "fi", "92bc037bde4de3d98f27b9534c1c09d96209ccb8108cf7c1c09b2d09118ecbd505e60a8aceb71f8e240c2553173689484e7e39b33ee325153ca55da3732f7673" },
                { "fr", "26ff7f1092e2c0e532aeee99944b5557df1759eeff734b5c6f2f168733284f2e8e286435410c1c95994b6c5acbf83d1feb339829bc5ef0f5a3da01b8e2d8205e" },
                { "fur", "46c1217d7e1d6577ac0d47aeac790ef602b8f9114bb357628ade2a054d0429bebd0c843e95b4de37963d0a71f6a10c74f9b5c2962de1a9d179079312a5a10db7" },
                { "fy-NL", "e75e64ed30e21f765554c2a8d29172bb1cddedced61efbccd4d2d3f8c837a87cd9683dea3b5af7d518496f945cfdde295af2080b1deefac442c9f660b2b2994e" },
                { "ga-IE", "4f088b42b263c5c0701b567e664e5583502df328d53bde458bf71d2bbee8ad1acf0f4d2c3ec3ae4b465f701a20aa93e1ec8669575c238f6992a4b167c942c387" },
                { "gd", "0e3041c75acfc67de62a084920f40ee2e6df01b8ab7a98598b2bf5f21f4ca982c209ba42b45b93060ea4e326d28da28c3019876d13b93be188a7c576411a7f73" },
                { "gl", "dd22e8babbbf79dd4458428b512ef1e2fb7dcf07ef4afc29d59d3213a2caa727c7118e8e3d37e98970a2271a15de9cb09452b989ad07b7dee21e122e30cf41c0" },
                { "gn", "f419dbe583091dba23f00dabac7a95d68320ee45421482cf78703ea067d77cecb8c2b018c474f0a4cdc4dd0a9e15a32d5df2720782d12354942916569d8aaec3" },
                { "gu-IN", "69edb87d89cb677ea9b66b2bc9d9ec2900bc474d6e77b8a11e6e659f6ea390551c758011bd9bbcffa9d105f62de8cc9f548d03d009bfb9f86e421b82d43e4299" },
                { "he", "54fb1a65fd8776230b2cab601e8ec19868ca4d592fb7b07849be348590e14cc4d951bf11500739a76a0d372584f6b474c9c7e1d73d686644298bbd87f84f4c2f" },
                { "hi-IN", "39a24b39bb9a438b0870c8a4ccd16f74c998f844e053e14b8c58102a14eac9f5ceb351cb3c8db1f01d82057ded442e66f37fd41546879a79b82ecd896528c9dc" },
                { "hr", "11a7a6ffc1a853056d236c32655f20336bc940d80a7e359beab5eb0c3568a1fc2f04a0908da161e114d8b100482f54bf47dbec8e43a1f59d9a5ebabfef999248" },
                { "hsb", "43ee1f9a3c9c99e232b92d86261b398ae1f4475cf6437e53ec67799a02fd61f33439eb64657bfbd2493ff4ee27f0f2696723024739e5a9367b31d827ded9c221" },
                { "hu", "28d1283d34f77a061a2d79a68d83aadbdade29a3b200aacf701bf867f141d763cfddb17e2d22d91986c7cd27f81f6f8a146cef2f8df797e1ecc7657f523faea6" },
                { "hy-AM", "63aabfc9aabe3bcc59dd00d8486639d2f22dd271d201ae00a34354558d4a1013bd8397ddb63515a508ac3e5e61234461f4c065c784937b68957124dfd3d92665" },
                { "ia", "c8e0575dc687e10af83eb64037b1b00af6d5785eabb19f09eac2724d2f113cb576d3c4e58a8d89791e7cf38e89852bfa9762c54566c260c7b01c86d4199e8d16" },
                { "id", "41ed23b1c026140e258c8b4d44c176e561c7e9ac0ad728326229005cbc54db5c8acc78f7e73fc9009fd3839ea5e028eab43c903f2b4d5fb9c55deae21b5c373d" },
                { "is", "33b7c1caa1b2b9ed0f4231fa68cc3e5e839acde910ba691628d6a7178d01ac95e27d3ca94f95203c08b29dc7359436d3356a5087bbdfdcdf17c2bd298520f793" },
                { "it", "3e727ea1931d09b16f1ee34d8c7b73e058e61b69939c626249cc94cb342d92163c41b48975dea39400f12a638b72ab3d1c304c3214e7ac87e2e70b28e0d81cd4" },
                { "ja", "6a6feeb9d53d806308180e782d127eb29fcad29ad028663e322d7265acd41456a61c6a2e65d9768c262e09eb194bb7ec18a63eed337752d5127fdb7afedec2ee" },
                { "ka", "4aa6b12135f0955bac0a8c8b6ffa1fa28be8dbfa15f6200eab4a5fc9940e14be2c5447239453727fd22bcaa708cd2c53cfee5f1f3f9b6a5e60faa141c0f44cf7" },
                { "kab", "157a687a6735b89038ad65bda180730b98b273674bea848d9284fb47d7074ff85ae11b5ea425dd378419e2d9677d026e9f2dc515b913155bf41f41f790aac5ab" },
                { "kk", "55fe2ee47da7d9188d603c9be0ec87808fb77580ea9d1bc309f2556aaab2dfa3cd5b63d3033ccf56edc104b8aab5c2efff8ff3dcce1d38c67f43ec0f22a4bfed" },
                { "km", "95b35bd626e4125dbc79c55c9848d1a50c0e6c1cf35f172136054d961563d409184f0b535a6d56d5391f0474d83821be4c967fd896eb88e072ff71a0d3e9851a" },
                { "kn", "936b8cf5a9a682d91b59c280f975a55d41fc20e80319789ea8a403c9b75ead7ab7e3c0a9627bf89945612c4999c8c6ae3a46c940d799c0ff9b86e1e082953506" },
                { "ko", "1765625e1df1b62d4c3e396c9ecd30ec25125a5f44af1dd19a6de1d9e8793d9404d2d21504a9bb98956b6486f70133d33cee12259d5a4d117c8bbaf2ec3c5972" },
                { "lij", "b05834b144be3d2934e4c9e86877d12bb7dcad5b29b7582aa91c7542d95c512891b3c5e336a11ef5f783f0e049aed539a73d722449528a1dc918156b93052a2a" },
                { "lt", "4db860c69866bd5e8cc7a0baa843efaf897995f4741aa2c8997c346a38e49659421e0b332c71b235c8cad826853f56a53b6d95d4b4d961fe1b73d5fdae2e740e" },
                { "lv", "e0ef4b19370531ec178ed869be29833543b7619db5acde658d63dd9732d5f6234ebfe7cfec5f0ef7fb4ee126bba391ec3efd3c7ecb38d5762a9effb4cd036064" },
                { "mk", "1242115bcd1baa1456289f60b7334bd5cbc56e823eb4487e44bd8308caaf0206914f2fda12798e8c975fb5424022e328e4f68a1708ef4cbb7cc45d468f2c5dae" },
                { "mr", "65ae4377f3d2a58f72aeee5140beb4ca424eed38caf22321d9c5dc70d3bcb642e04cc8aa08bcc00c6af9c2018ab45f6414a496f4a8c026248a001ed0f895c84d" },
                { "ms", "07060b3e809447a80f6e384fce4190c0896f8b08323c60f6ed401336a72239127ab8fb64dfc6c8a522da1356540e788f5ce482d0971ce2604a63da5346c53fbf" },
                { "my", "77c203868cd4ead8919536c7feb1eebd441262fea0f29d6649fa4d01234bbd4e58017f9362f719b5d01e19da883dab381545399bd036c8d3abedd8fdd25e35dd" },
                { "nb-NO", "8333a7ea159c91ca0f03d1a6f118d01012b300bfaf857053b8d7a1ff565d30b95a2eab339c4c4d87b449ac17a691837839896ae14bcb6f5634c552664446d884" },
                { "ne-NP", "ca3b3f557de5ddc363b7e8b63a5f167b45a4dcfbf30794141af2e967bb9c15ada69f0ff82df7d8033a80003b067be64927424d984e184e0641204f858b9fd4df" },
                { "nl", "b25e1a1e5393a24278b033b9a27f0ce241a7a3a4738eed52550cf451cd1ac300a00f4ade16b618e9f1ba0bad8c9ed805c1437afac3faed43a453513d85616561" },
                { "nn-NO", "51b9a212b8de883bc7113d79a68f0922062ba3d41249f584111f9df7f1a54619255aa9207abafd50d5ef014817ac253d0b7bc98be3473dba076387b64ed0a994" },
                { "oc", "30e6797e4edb4335acd67fad977de8c42e537412c62bd378c532a92783f219d54f9b44961ccdc79e96b4528a0923af3ddf10ce2dc53e3a81961f0b4efb70d9b5" },
                { "pa-IN", "fd9eff8b35e3dac1f2232a0cdf0a262978f28ffa2743da6640c40f43c7bb604b2f7ed6c324daecf0e7c6b6fef80f074cb6a5b2a25e9b39a12958a3677dfbf175" },
                { "pl", "b13c9d71b333d41302936ed9ee8ebfeb14a23a72999e9c83cc3afa0f88493e2b6538e35891ff10f60bbc4ea4833d253148870837e7727236b9e6e0cfeb928980" },
                { "pt-BR", "d5b5b2b035bd907695ea616a8c3dda058239304b43fa28aa77d19db92a3dd2c52cc902791fbb24ba6a3ad34e3fdbd0680b3444afc4988a7a24840e4e1c6f8c71" },
                { "pt-PT", "baf53aa9c93874eb99215e524b6afa3190457884df0af6537308eb06bab9284b3ad2c77c2814f4c8afc04df5492a8e8e847b7727119002dbcdb3efbf06124367" },
                { "rm", "41040b73dc580d8a26b99ffa37b25c90aee18c5b94051c5425cc7bcd851c1ca12910d473d726c7aa629918fc40c6fbd378000d2803f55f92d76f96851ee044b5" },
                { "ro", "23b228f46d182d9f648106feb8b54c03bbb2f1fea92ba813f72a14b32e00fc404630bc5445c9e75d69ee15d15ddfd68a0fe0d907079f469270fa13dbfc45616d" },
                { "ru", "e49118c8fb7b582d4a0b2b8af93d1a02e2b1144c8ec48abd8a86f432c2b87f1f6b3a79511ebec93b631cb5f62785aa40afb183f3629f1a3e28c131f27a1b5214" },
                { "sat", "0bca17bc21ae01411cf6bac08cd1f2aa725e0c1e79bb5b38d1daf4abd362ba7a4b71e606594dd016ff9783daa0e7d39316dcac93d7f588d8c3d605119f4e27a7" },
                { "sc", "f8500fae10fe473bc6b33dd6aa54c42aa6550e548a53cbe7789b245aeeba2b095c304adabbb0ca07d52478862e1a6bebfaa88dea2e249b04bb690f1e8c685fbc" },
                { "sco", "a6a660b2db480728a8b7ad2ccd75b1f30f076bc9c98cef8c3225cae5a6019507bd9e7d4936f48bed858d74d6371ed90219e0c0df348f285cf045b8f126eb5637" },
                { "si", "c0d5f0fd149a6af6b57b19178fe7c66fb624df44ff8137ffe98efe20728c8ad1fbdd9c0ee8a66e8b90b55d9e60ae4930a5091d4fcd7c9a6088bfbeed5401c7a4" },
                { "sk", "3ca12db7fffb74e3526d1bd479f6644b9b9ea8041a1f7c80d265551395ac5e29fa65792a1eb75b38e9f84e7ef6b514069c9165626deccd03cd7e5a0778756238" },
                { "skr", "adcb828d75ff0592d01a84d2035eedbcc4801762ebe2617d55a3416f3f37e15c85a43f83c9cb8b63bba786add76daa6424664637a662c93930b174b60df7d228" },
                { "sl", "bcb59629b15ba9dee827515d70d6a6096a7f2fe7d4dbe1146b9ddbca531d1a534b11afbff914077802f9cf5c2818045bbb1a3ae41d043ceacbc01bb757cb72cf" },
                { "son", "18bb8e0437957b04ad3f14e3c9c6d7d4c64c7495e82d7fa1301db69a0d187877680dadceb4c7cc11d54d22b9ec70fbf46859e676b2b9caaaba690c2db4bee7e3" },
                { "sq", "6d4497a7169b315e4d6fbf135dc44344b71df730f295f453cc1410baa3146a5f8bab62c83ce03f3d3b44106c95adf952c17987c36e7e677e44d70dac4f8f1086" },
                { "sr", "7a44b799e9a84c378d44dc72b8f5e40c5c852268f952267703ec8d875a7520948df845964d7f477f800fcb4a6313afb8599fd07e4b8241588ef914296d2150cc" },
                { "sv-SE", "ed50a1d5ea8165394112608a50a0f2eeb5c750ed493f8c2c8aec4a1369770a34d833f93cf9f429b120d582f4c79b187dd18ce1f81b98d5162816552c25998e46" },
                { "szl", "0a3eabf0dbf77d5007c88b62bd6e55afd182281ec0705e69c9583f409aa4dc195b5b7d937c99ecf61a71c0d526d3cddcafb75cd022e09f08ea3a0f982ad17b1e" },
                { "ta", "591031356ae29ed093e6d13e217842530142d4dd5efabf888508f5f340120733b06e7453a3054ffdf49d8c6a3d7ab7d2515174bb57f03ae81ac4b6ef6eb59ddb" },
                { "te", "dab4afcbfe523e397134e466c200d395285069aecaf1107a4814333bb8fe3b2eeabfcdac604ea079e179fd5b104bca0f0f143feb9c4ebdbbb98640c284fc9657" },
                { "tg", "ed6deb179cf78a2b162628a14d1491226827c6b853464c2b6fe199ba5604d12b2885ed54fb04820980f971801f3287da12dbcc54ebbbf525026b0d239fa14580" },
                { "th", "76bd721334706e74cea57e100d7ee71f39218e5e9b058c7cea601e07b71073d212bf9f2c57aa82229bf663e9c3e71b24d38981a3f493e68b7ed85a756ad15fe7" },
                { "tl", "63728ed6a469acfc64c7cbd3e8738b6910ddfd991574423e8707ad20cbad3818268bae7010d0e0d2e2c3700f0d177de84fc4d1c1a019364746949a33b6a27413" },
                { "tr", "239c0660aa9e99ced865425330007a90f9d5456eeff77b03980c6ad04f52348792b212a39816cde8266e6926d9f0c7abd38d1d46b38bc291f6fe737659cee0c5" },
                { "trs", "b469d407fa30982495b56f84de646b02678af974a35b8edacdd3efd3ecf98f7b38d3db871bdece509fafff3ab6661569bc39c40ae9133887f3dfd4ca779f5207" },
                { "uk", "0598f31fb5a4e374edbce6dab95455c48486f7ebbd5ba62c81f586416b6dbaf57bd3654197911a7a7835cc2d9f1730de8e8b004082fbb6306d19032460c4479b" },
                { "ur", "dd85cb22da24071a113754382626267956aa13f2d4b1dd9c12e164841c41659f632632930c6da693b23f2d5fbc23035167e945f7e8e70e588cf3ae2f0e55e88b" },
                { "uz", "96e685fc2ee92e909bab93f55bad8f87e44b7b2242d07c826cab4127506a06fe61a6bdeb88bc0067f4d838f08bdb5daacdcb1f65c73d97d5b489ff5d945554fd" },
                { "vi", "c25151c7e298e59b2185ebe7ba77ff4e3fd576aca7b9f9a30dff5f2ab08a0ec2af8419e6ff9cf261aee921ca6c4b8f03c00cff49b7f443da46cd28d36541771d" },
                { "xh", "14d337ae37a2ff15d81237b348f20f1c41b7beb5ec9a9c8cb62fc141bb124b019129523fac73520e86890d979a80a1ce74ce96bd8a1baf96c1171abbadd1a36b" },
                { "zh-CN", "8cbcc0a3af5863183d28889f68072ce27930cbc5ba7fcd6a1ca4f87360d2615dbecec75ca523c9a06ed32c9743d07d73e468b5544e4880134478e7a7a926c54e" },
                { "zh-TW", "974452dfb3a6fd99d8f14b9ca561f60b7d75f1b9715c9b3b3ccd36970e98c6e770646303ff7ecbc63d5f709b401a78246ca35adc43fafb58675963cd6f6abccc" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/131.0b6/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "0b1ed985f19dab2a4892644ac1d87b7abd0d94fb4a440ba0fbe8de86e6999615e7ad62364c04a264917b6a519b563a471d0f7b2aee63b4586497b3f7af90f127" },
                { "af", "6db11d373fda3fad2124c4815acb480f93d8b30be1c3fd171a7b47cfa7fddd3128eb6a6aa17ee33256d8c8e2fe56589263ad6ea23a22d8ab04014ffa6789000b" },
                { "an", "7af613d4a746b0127657664fca52493074e068bcc828c29fd9416d7b4500b7268ea1ad1620b42ae2bf7d8f16a1717a29a8c9a4f041ff5700a707312ff9a864b8" },
                { "ar", "6b6d53a130a2487ea67c8943a8ef55f8231ee6b8a865ba4f6bcadfa6d8cc44fd94d4200b2a660ae9240e16c4b8025ccc6bc6474b3136a4330a8c126bd6c8a6ae" },
                { "ast", "df51d1240ae5eac136b412bcc80575ec064ee4b7bff771f7786bf8670216e834b5df4ad8846dc2a8faf46ebff741ba4220d52f8dddd298335f756b46de50ea3b" },
                { "az", "9934b00972ccd66ab96a2d49e3b1666c870a7807ac59868d693cbb3afc0752515ba65de1e519c251dbacb79960de0a8af69ce8ee12de3780420563c3f89e8411" },
                { "be", "fe181085d936ca7ef64b9c7c8c5b0cf7fa542e38161f5c70934ca4492640d10c3e9ef466f27a001678aeb89cca63abc069bc33438cd25d04a9c3f5aca5bb4505" },
                { "bg", "ad2d983cc1de4f64f2b9df0648a5674cd7d736e0f4e8060e9030a253d97e74e6459b6c57e98b95a4161f2149fd79a66bfcc0f2d8997cc7b32ab34cbfb47b1b57" },
                { "bn", "43e8997ccf1efc96189a6ab5ad9a314d2dea50e55159e13fd5efb822173c1cf3d1ec89dc62ecd8bfc063fb60b27ab6516f1eeac57e220f24c0e22452ac4314b0" },
                { "br", "5c17923917693526fbd4b808412925fbca843a79e0645cbb42f2e4c62e09e098e90466e7d5dbaf8d8fc71641baccfc577882349d050ee633bd9f5a37c7e36c72" },
                { "bs", "a3f3fc606a06747675dc5ca3bbf15ade0ab5b34df6ad49e42a0aa08c516ba31522c9713c85b203980be1dff7f359a85869a8749e0dd2eaf1ba8191c2d030dd81" },
                { "ca", "7fefdf8d66db1a71e6f943f9cc97c4e0fc26773fb76fa7123cd5ec6f81db9e043697e0d836a5a53d1a4aa314aea41bb9605a314411b53e4dde85b6a60b3032e8" },
                { "cak", "6e7a865bd70c8ba94c54b9c94f8b585ea108688c90b568df7df0b213bd3399a2fb5130034fa6082ab1e29a3de5483e4dc442a8433834814295ed2e7bbba47cf2" },
                { "cs", "d56b75bacfcb8a37cb230b99b5cdc61d45136e47d5632e4806472e28ce5fbd6362f25d89e8e2b97727bb8c59ba0a7a180c155caa721551cf52f2755dbee03fa6" },
                { "cy", "705cdbd134d98d8d76e2d331c4fcc582bd692fc00913932415b3af258e33c1c806f791f869f2ea2177d282d6b29d46a667665fac0c3d10942f01d77cdf01f88c" },
                { "da", "a4c945e17c6aee22f7341fa825a2171da0ba47f3923700175856824c656a29a0254bdc300bdadf84dc6f40ee73e195220cef91dd41f4cd7c8b850a846106ab69" },
                { "de", "897a05176610bc20fb70882eaede5a0655dcc963931a59db5f7b11c9e21a2e3b359e5906c552a418147d206aa2fbd0c1c319d93c58d918400c613086d2e48830" },
                { "dsb", "d3d668cd82d6b1c892e765bdd526046f5714fdd3bdf7e049bbdc3750779307a332d812c992c6c85192b9911044dd0500e4ef9b1101e718186492845fbde68864" },
                { "el", "345100f2885261b5c29c85cdd0e074e436b4e7c7943ad0815d223e338eb002abe6bea32661c07eac30c62730825e7a56c8223b295fd1dd5c17c2ff118336fd40" },
                { "en-CA", "6cc9d5a5ca66ded3b87076bf322ed17d238be07e2dcc4c420b26bcfb500c9644ddc0f6d2378261cf9c9784ffb2dbad81e43c011b6033969d9875eb6207fa3bee" },
                { "en-GB", "699d3cf0a1a5c3e6f6422ff522a54f16ce963eafd9a11cfea5f1a4762dd43f0698e92131ed29bfc763382539dbb2f63eee8ac7329d1ee2ad91c66f0798924beb" },
                { "en-US", "52eab8c442bdbf3afa42608794296bc9abc50b8b4b360d20f7eca0abe8ad9be048ea899ecff22059896b58d775e6e77bd0bc835653ba814863a0c75500a9aa3e" },
                { "eo", "dcc393a99f11d4f37b7df01b4c1bb4abef36d054ba563a46b30a0f72f57433a7de74ceebee66bcdf8eaceacd440c139f48ad1637528b7e225871f17be2ed8f64" },
                { "es-AR", "d91fe7692a04734f352b6be8743040ae21d1e27134ad0bd7bd6c80ad63c0b25924aca24b602deaf8b29a8d4d35d3a3488fb20aa04c63ba040a5157412583da6e" },
                { "es-CL", "1be5d9b37bff4a90587f9523b98d2c7eedcbad58eef3b9cad89aa50298b5f1c3100b6e532f825527c1d30a1a84c6a196792956574fbc178af1330ebbc3af4793" },
                { "es-ES", "28d5a4b24201783cc4d78c0ebc4edabbff936751e713db2e2555868e65b7abcff310373359ee0645274d9b24d5a2200ea190c55ca043ff8a02c22b2276ffedfc" },
                { "es-MX", "1043798a1692db3df5871425d0631f1bac8a9a39db1fba6d6f44f8966cb5b10e60ecb9ed8903670a00c53f59357badb663b88bf37e089d8104492c3a20ddf200" },
                { "et", "80605735045cbba2032371b5dc8cef0fa13800227eace00f235bbc7e84a91d8dae7cfe3163f9a0e7cfd9e7165acac8211e7e85c86ef89125829e4ada88a73041" },
                { "eu", "f7fcc704e3130b5c3ab186c4b3a8c560883a2c75f13c87e835e42fe206de77ee78bdf919b20ea621023d1e1d549f818295c2b1bcc9329d9a56385f0641609439" },
                { "fa", "8c0312a8ce293ffd9c93e3a700fa745e310a3c573d57bdcb9466c165e7a535c31d3d4360187478daa694103d2ba17e0ea6ba1ebacf5b00612aab741181497784" },
                { "ff", "77e14599591fd77ee7c816b8068a93d502b652e5b49e4a5ed0e58855b2a1776070c68c1ee60afe97b272f57e9326c3f3c2aa21c4c4c31920556a9bb8a7e8212e" },
                { "fi", "3921fdf87320808a386a8280df152ddecaad755e1c1c5e4e7b583e1529660f95895cd8f104344906ef587247b58f823e4a441c5eb2e1e0f6eb734c50bb5d3201" },
                { "fr", "da362cd7fc30710c155f83955a94e197abe49f9c10d42207e1e397bdf42e89c55a81966a884adab65469e8b28ee1b4478f9978433c45e0e7ad2bafc913bed164" },
                { "fur", "d1bc1a37aa8914426d6a61d242411d27d6474aaec5f7c5fc42865625451c343ffea2aa93e91f7c764bda38ffc50cf5a097dfa5d72ae98f945830ed1889480c9d" },
                { "fy-NL", "92e6451bf25f164506b85920800911e2ec9c4ede6ff47ec92d4294553e2f8dd54b511f601961857c2911f2fb195117a2337819a813c763d60754e50f39b330e6" },
                { "ga-IE", "e53c12f5a1099c07591fc924d1f93fa90b0be409a723b5c8f779ba6c61e010f21360b5212c7e8983e9445262e01df4ee87bfb1fa0b854bc3e6ba7648638dea69" },
                { "gd", "b9b7e7256a090647b2b053e6c6176374b432e0de9563db84a377bef59f403eebd60442b2338cfe476391898c0b103685a8ec35966cfcd13c14ccc14d8737beeb" },
                { "gl", "1b816da8959351077bc43aafdbb8ba3a01254a30639f8994dfc3d40eba2a0fe0c4bb6adece8fa497ee97640746a52a251b8ffb1fe3d19aa60bf8aa610701ad2f" },
                { "gn", "595a06b5745baeb512f9651789bffbc41ef4631b11363ec4341afa2ed35a6e789b37d5203f1c96236ae55a460e16782daa7a2e9135e789f8cf22d0d949c962a1" },
                { "gu-IN", "d2889f080e9ec24f775a86a7671683cab0aca2588c1ff903560b6a0b1c08f2b86d1a90e55348e46b19d83c6bbee44c66663f4d94f8cb93f4fd485403c8754aab" },
                { "he", "60024ab0653593b6eb2d3674ac8365e2ca3bacde68cbcb2fc047a57aba56e7c75f0b71fc0141a6bf879bf2f4f365b1db695e94b4c7ef7edc043bbccae579fd6b" },
                { "hi-IN", "db92aa6b51c3201020e8a51dddc8093823d2bdc0f873c58c3acda25025b746719c0266bbad0c37a74efdf723efddea08cf6b19a953b5ac7e0004d362007ddd96" },
                { "hr", "0f4f31b7a052c9f878dc453070fd0fd4e3e66b80476ff4fda78e1cae9e7e935d31324d43f8a9750298c04003b724ca939742372abaebcc939118114941aa2cd9" },
                { "hsb", "6f42c90184ead095e1ef7ed7a15d6e58472aa4977dac40a73d4d3633a4449e3ceededce22efb0fab1eb2c700f69f85eafca4ffb5778d3375c230b9c8f01a5642" },
                { "hu", "f6c1dc5d6e6b55c6f30b96ded4dacc3c18a737a4fea3d6e43a6de3f2911c2ab47d06548205d020e176d247b22c16c8675f0aae12b381ef196b7cbfa864ab9a57" },
                { "hy-AM", "d93b53fddf48aef3924be9fd6b811e56d5d7cfefc388e795774059cec97a2074c581f31c3bcdfb6f5ecc8d1e8203e94c9a4a820e46f862e0a24bcf61d0db1f13" },
                { "ia", "b458aaedcbf6e7ec4b9c69a8650ff62a7747f91fd9b9cb30906b3ddedd07cc7a7303b5a8777b3b50a9009bc1e20aa8641bf7f523918627348aa7fc2a3d04d1dd" },
                { "id", "7a6f655bd8aecc8db606a3b510bff609fe9a626165e0b20465c21a631a612484783f6e21b922abd4e3d5b42bf8b58994d6b48b4338f2ecef5908deac630c6667" },
                { "is", "be3eb35b0aa4cf72b5e96b183b4a9fa0f784c4b1dc940c9b41d55e3a8f9e07ade4754dab7f11d2881b88d568602e349da1804adf986a673874632b74f82bf5c1" },
                { "it", "57b01c09a1f1af71308a011cdefef5a83dc003e6d2203267991bac98ce4afc24299d9cbcd545f962d5d592bd485a84a0d1a1882f14fb7321e895c50c700edc60" },
                { "ja", "84fd3b2acc98c582882040e0c9cb67eed673f90c0c7713697871e55e2401a3e4163399c09beecd769b1e3c538a7d105a475833f7a7c9585bb9a549678398ab03" },
                { "ka", "ac7d934c62d3d0ae74504a6c8bdcb424e9bdfe7ae42fe432abc7a00a6767ed764cdf88fbd6a7f18af8588dea22f81b030a2f5622ef3f5c5a85a44ebc762c56b6" },
                { "kab", "f5e1c2242986cd66cc3fd3b1269dd2e6b6fded68ab0a7777fda6ed4718a146eb53bd5d341549b393527ed8c3f2d19b269ff227e1064805e673b2cdb3cd3e4673" },
                { "kk", "20669b255475ce2190e8aafbb58f7688a3c39b314177f4162db5f25b53ec0a8be6e49a9096ad0d8959e71d4f3a3eee52539541a792b679db51612d33186d74f0" },
                { "km", "b03b25e424d382218fa003b34a16776b1c212c979949dfdee2c099328647337d6e0d34daf5785c294c73a3e79eb192ae74ac11d7459050e338283c32d7eb3838" },
                { "kn", "b817651f839ec0fb73e1290cba5cea9ce201d61b85850d3d7eafcce09918712b7acdc188c31a11ba73179e2c0273a8c20b8ee33205a885021887e3517acd2ee2" },
                { "ko", "0566b1dfbf5b95e8fc9656a836846b1312e64734e8d04ff1d9c354d3028b8fcdb024b3cbd78f51932d2c02be012ca48b4d6e3335133be585949c557b30644706" },
                { "lij", "4fe9d1d7c77759037f8059b000e03c09c3e748052161695bc5c909e99a889158ca2b7ae37c02d0fa70ef1d69b30ec0221359bb0aea03353621d74078a9865e60" },
                { "lt", "b38e8f3adc953263ee2eee0b5bd0182fbd63a406a5aa2524cb4ea1fe62ea602103154a1c05489dee683a99e0fd2b62ee3e39bc42c36462e726aa81ba751b8383" },
                { "lv", "7c9f0f7c7ceaab7848567923578e8b29e3ea6c31e2262637e5838053006ab919e61cd4a8f4155886abc51a7a51f53f9e2eae28b2275a41803505d3080b2c6bf9" },
                { "mk", "f832752b62339bd0ed2fb78ff186583f222bf4d35a91ba8ce6559c06c0b8bd849a11e25ce1d7b8ee9e300ee76a32f06ed054c7abc2e84b3c47d76ddde5d51791" },
                { "mr", "e48dde3eefd0ab5ee8ccbdaf8c8dd782a4ac7c78476d906eba1a1d8ea0aca44d0d9d7d5a3395637be2c38c0bf537be2be030dfca7574c1983532c8bb4695a463" },
                { "ms", "1b80382a01899353f751ce7f5214e98465f3646408410b61f6bed7ccf1237766ffa8de903fd82f2a14b61c3dffcf4305a5edd3403299b8f0afe022eaed68540a" },
                { "my", "328f0206c56b5e72b184af782479208036696c5cdb1aef47a4165f33baae425d2d24c884dc64c1b9f193476ea947de635114fe7c8b53362e3f328a930bd74fb7" },
                { "nb-NO", "7208b37aa45df4d969f330c571ad8fda6589351f8a27a89c2df773a23ec669d8c0a586611037e606a7f3985aae055934b488fbf31403f826088ad1d1c797d6a5" },
                { "ne-NP", "06802b492284c7236f98a1896676140d35c609869fadf7f96d4700a65134fd200ca30e23006d14f3890821d382bb1ffb7f2d777e2483f125b6c6033017685c9d" },
                { "nl", "c334a358aa6a26ce061697b9d52d4e9770e3cfd200b2b9b62113179bee2c3666b741a050163599736c9f957e4a6b68b999bd0426b350981bcacc55dff513f3b8" },
                { "nn-NO", "a154feea72d2567f35b4113463aa466557c295bcc978e5c2d50ba83d939a55e58690793eecf2cb6965cb2dd772368ecc66f8e5371f2ee9c0ccbc15b8ae6957cf" },
                { "oc", "83c675c696aceb96307e59379b21c6932266cced505cde13aee2ca4875a40d3dc1a8a7ac4e5f89ec3941dc91a354c25400114a7b431ebd217609e86b0a829e2a" },
                { "pa-IN", "a32411089b7f460a9523f1e48946e0762583800f57bf316da8cee439a712fd98b718545d482313656adc53a81054caa2d834b965d4c51bcc47f524153b7e2256" },
                { "pl", "8ea7631cb4d88694f4f399d6bd8e061f2149d806344cecace09828afcbc66678b88c93c7c42f12344e240f5a54819a0d432b3db95b544e1a5c274d400ac58dbc" },
                { "pt-BR", "80ad4753b45c38596ce15776b93a8ffa159b2a23d3759b9b7da40933054e25ea5fe6d5fa96ec292bdfe453e7a383fa6385c26a297bbb0cf1d5eb3c73642e2eff" },
                { "pt-PT", "553d61aacb2c4c9d7a73d615787e4cf87577e9b91704ae90c841e9e843f85544edac7898f8b6bcf400bba22bc29bea56562cecd89c3b97f74e387f309a71ef34" },
                { "rm", "4f33ffc4a650d76a951680053db628c438c874d3d058ac509b858f1e390d33444437aa35e1aa8c3b272b2b36d74a56b8c51c518c4eb1251068b9785724b863a6" },
                { "ro", "80079f1f7cbe8072b41b6aae3fb2e0adf8a5cb9e19c0840e2327677558b29883d951b7d0fffacce98c0c93b4f37d3a65163bfb695d41d17752e18e36472f8a0e" },
                { "ru", "089efc391857d0388ca62268b23a0d99253c4c77484ad567df8416189c0c4d70e15ebc4a931537bdb2491e3c939e35d458c350a445a34596f127285acc44fbe9" },
                { "sat", "97ddc50ef4c08f1fdb1a8be2dcae93a980210731465ea7e2a18b5ec8dd4511d6fb4cd23ddd763684ad976483c72700409dafe26f6f538662b88ca263df84846b" },
                { "sc", "aad1bbc4d8f5ba5ce5f82c49a8843937b19811d84ade26ab56de97dc496f05e1fcfe397374018f27acf153bc26da949bbcf7654df28c6dcb4bc6f4658038ac75" },
                { "sco", "8da8b7a0b1b9caf2c98eaaee85a013b22791b0eec9fdc764c8851680a044062a1146a86892f047b41f165a3bfadf52b62ec078009fd958e802ea323079842ee2" },
                { "si", "b3319c0a4c3bc3cd19b193e8db6bee67177a8525911af05b8a274bb8f176230b728e3fe9020e9d2a195ce4d70b1d8a9eed2ff7e5a01fd9c056f1157856e5042c" },
                { "sk", "678d3b67a540d30945c180ed761acea498f09791fb2fffaee3ca6b67ca861c2043fabefdade25a507e1b1b1dcdc7103629f8b6615083aed09ddef69d1914ddfc" },
                { "skr", "fe3b6eaa19a74f23abc642d88c83bfd9e8971169e883128c7ed5c64303c7aa26f1d36dd9f1d34b397144e944aa9801465cb5061d836deeda3c5bbc57b0277e2d" },
                { "sl", "ee80f402f6bb8c631e4e83532abe661d780baa4930e0e0ce577eb9a6c090864fad6b97f5343301332189da2276d26da8d57c883c74c05831886c3b384f909ef8" },
                { "son", "922f9b567b09cf8363622e2f603434978b6bb8f081ece3dc99acfd17682cd3196d380227c4655249a843e3e0c9ef41733c3e7d80a43c8407e14c67c25278a6a4" },
                { "sq", "4406cb7cd81eb0c561f8fd6cc7bdd912387cbbe5b34ee92b9cabb0781b70a5b4c6156f6e62fc6a6bb0aa87c15a3ebdbd2ad7eda2b85241f7780aa48d15bf22c0" },
                { "sr", "b13c87bbdba33f61957c94dcbb08037aad9fb5a62590932a688c98ffe9e7486e49c0339f4df21f0b751cbd07505d6cbc5d51f1debda927201429872dc867767b" },
                { "sv-SE", "4c2df9165c6d51adbb4496538dd42e662a90ddce2cf5ad6045b27eaa9af6c4284dca5688b80186c433dcdeacfa9e976989a98b3e401621dd1940cc4f3098318b" },
                { "szl", "241cd61dfa484657cb88bc5680e114d998bcec95b96e756618094d92f862d51596c77722b164af5fa09963e53f934a5dd8a45137846e27e0db7ef4e8879c1a6f" },
                { "ta", "ca82a898e72426c857160c81c26dbeb3849b9eceb2de9cae98497af716cc6d07664fe70b98a49b04dc6dc819a87440b4f47a1b3b9affa1712206e19f4eb47a12" },
                { "te", "c32e7bb03186f0379d5feb99b153581b59e8933bec97c8d504b8ec65e9f80492ba872743af3a7ee36e95c9aa73f9a60dac955800cada96cb9c928ce73b8c08f8" },
                { "tg", "a95dcc617deae090d948df2d6009fc0a7acad08e0207af709088eb0d4a3723bbbfebf1f16f54f24dcd52a5f2d51819222c1144ce6dc760bb4a937f2ae191dfae" },
                { "th", "230b68b5fcc5cbea1fa9a1df755b3c397c1f28f7c3873c48509dfd2eb1d72e4ad8f73a45009d4ad62c23968cbe553358a5395918533de48063825ec9e4b225ea" },
                { "tl", "5e731471f51c65dc25e7ea6d94ad1bf1b7d1f4783081d29405fe5e5c05a72371403e00b25339d62188f4a67d66efa212f9d8f67178fe504eea59d6a20854381a" },
                { "tr", "fba01a6fff671657ec52584b86d22b350c9573a5e59448a63855ef7d3f5360c37e1306f7ee0298d3ca28aea35b3bedc62295965f37e50632b54133c7db5e501f" },
                { "trs", "9add91b5ff13eda89fae94ac125cd70f989ec295dec07043f8cc3682252177df0c2cddf013f370d6fb1807a52544eb9ae7e306f34dec7f6fcf0de3927bd15c63" },
                { "uk", "28b6000fa29ae0eada8eb0b1ab474c846bf1384c90e0e0f2efa60b9e0bc1d5142e974096df5b92c46a51f18a8af5a6d78e20fdd881702dbc1f5fbd7c78e53fa1" },
                { "ur", "aaaefe75874942e3db342af50c3ddc0eb8f73840dae8abb60858b621e2d49d437ccb62e3445d3654affe8f6e9b1734833f776f428a885cc820e4c4cd66a3044f" },
                { "uz", "b06e308514317012585c6aaa8355b4871cb785aa8ac56c20e85d5ade31b1e876023896b2e87d184738522c1f9447f8858e68683f8c042b74be73dd793d4426f4" },
                { "vi", "0328883aa791b18710254555c0008e71cab98fb5620061d5f404ae89474ac5a11bbca31c6677c71ae036541d132991fa7effd4a37d2a2ec311decc78ad3cd959" },
                { "xh", "491624129877ce8a6444583495df600c9b606c43221c8885987394023ce028550851320629b3d78cfe220df20941018d747171072aa6192ae4010cf64e872576" },
                { "zh-CN", "afa2076aec41304a1fa6dfdd0232843f3e9b95af2bf63ef194363280977c117a12a79a05a5c18b8fc50bbd57881295ab8905fff7b903cb5d8e2ee0d09b804773" },
                { "zh-TW", "59ea56f32ca45fd449b92c030bc4de75640d83ae1c6c7fd7814076ee5aa7cf69196fa5689ba4440b3a3d2321d6e13aef081382b6b5d6606bef492ead1640bf8f" }
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
