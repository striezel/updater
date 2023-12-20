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
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using updater.data;

namespace updater.software
{
    /// <summary>
    /// Firefox Extended Support Release
    /// </summary>
    public class FirefoxESR : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for FirefoxESR class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(FirefoxESR).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox ESR software,
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public FirefoxESR(string langCode, bool autoGetNewer)
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
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.6.0esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "6545ed655ee7805ec3fd9ed83f576dd364880f451a06b281087e51166f2e8a5760601dc614faec20e095dd52742a678085ff0639ad74f26c7c83b53666a032ba" },
                { "af", "8e6a890cb20b1e59c73e479bbd8c78b81d82c142bf6df8034fa2623ecffcacce489823f374d285dffba6606807d190c59795b5cb2e0195af2aac4655612b0d18" },
                { "an", "3ea2caaad2a06e62d6e1f8f698264a429b092fed2372e2976927e4bd2955c1b3e8797fd2a80399288b8944863a8471e48c167ef711b94d8f2cc6df7e1d906101" },
                { "ar", "78923af98b6d7d580de2b10732ab60be7e859625969e7819d20d030b17818f59aff6639b623cc9456074a51da51e40f837b61d7dd2d3187285d1299501a9c609" },
                { "ast", "8f3d7991467ddb775effa44fc0f5124563ac0c52b218cd79f8873bab65a5d61a824ac0c9c525ad2625c5dfc39faaae888afa4df78127cd2cd49d1ea26a41719c" },
                { "az", "c54124e4bbcf945451986953308abdbb35323ab4ca3e0fa340228cefad337feafdfc70c45bf6d00d0572d0f6f0f005be70d1c6e326b3c705633cf788631d8e46" },
                { "be", "4938598678d59fd4a8d9d0e4aa0393dceeb592625a8ac0a98739a1339f4aa347c8cf14985eac9eda24985ac8a3b6b2f6a8a46fc2bf885cad1efc100afc4efb84" },
                { "bg", "e64e34e292e2308ee886ff01b8d6f2ee0a3fce8c20c3cab3145e8f05234779578cd5738d20bee4a985a6282fed7aee8bd25609ed08a5d2880a95795a0bd969d6" },
                { "bn", "3817e6fa634e430739fa47dd622468a598fdb4c9ba4b447ac72e837befcfd84673ba2e3488576635f40772ccf2809623344dbff85bfc332e3dd19addd33c5381" },
                { "br", "43aca7eddcc07403bb6fe15bcce399a7a6fb4a08c2a6f2e81382efcdafc6300fff283d2dc9319b9ee8f6806a541611237ff76beba69e9fc352eab2919ff0ed1a" },
                { "bs", "fcb0baef95fe0d3b7889109b04179af41404f102831c832191feebc54d36356de9053b3b2e36b516716dfdf337090a9399741907a0545c666464d15c37bed4e2" },
                { "ca", "ab6776dbdb437d63d4e6aa1cf973c77065fa6eb74a1050f26718034e63ce68fe107ca5068c6f2ffb4183778ab7eedd8d248d15975f51f2c5aed1834fc5da3f59" },
                { "cak", "a435b3bef5215a574a9f94ef475b5caecc3a8aceda760738b9db4514a5c4d6cdd398b817dd3e7f30877751d35ea236ce6e0a8ab89e254c89983c3e3b98ec7cc2" },
                { "cs", "ac1e79757e6ca78aea42ae6a7dc488a8f4c28227791834c64caee9baeb86ac525057e44fa4a25c40efda0b352fc510ed910f93fac1481215c27c1994a795393d" },
                { "cy", "9da7656995a515c5a2f56b45de5e51cd808d8eb488faadedf23e224666bf67e650e4287a9bd2389605bd7f7cfa6ca9fd8e628c25bcef761f0e9d7e07527cd198" },
                { "da", "46fe97232544cda0eabaeb1df22e840078c3a118b51ea3d1f9f3c0f56bb2328ccb2a009fde68dfaccccad1c13ead2c23272d7b5d64e1df11f30251b8c28baefa" },
                { "de", "48b471e133563502ac016512fb6f2c03e35fc0f38f22cf880ad5f7a72ff7b4f615413f237108474ff281aa18c42a2442764a834dc6ae48fb47dbcf8e09a05f47" },
                { "dsb", "29d2400ed106d967e03d7c4052b92a9bbced2d5a5dbe4c0abb3b2f7004de68c52459b55438b18dd221207f196d5d901fd8456de428762e5128d11dcea0569707" },
                { "el", "1860a4d20bcf26d5d8ae757387a58ed6e931676e36779c6e53ad5be6555b88a230bf85c34466a7525e7a1e2036df555964038dba5ebdae49eb36071d2e9198aa" },
                { "en-CA", "1424cd0451c4550a3fd06da4afeee6557b96ede418d81d85b1a3e1f14e30cbbde93d8982f6b454512e84563c9470a82e120ffaff168694f685d57ae68eed6913" },
                { "en-GB", "ea8616f9f0f07a63b794787c3908d8948cff6edbe5433f92e395a77d6e23ced457f02b16dd511bfde7fa5b1a57b1c9e6106bdced6c273a98e9a4c42eed53ffce" },
                { "en-US", "59a3286a08ec75394131618dc4955cc0b26929d5b780d416d3980fe90c7054aae6ba659b361b144606c6fff63dbb614838195370f56048450ce72ab83d1cad23" },
                { "eo", "bc5aa9ab160ad998d4242db74fbdc87e64c8799e409dd930e70fdfff92b707e26042f6ebfbde9f3504632fe88fe246172dff0c2f6fc39c9f821fc8b1fbd764be" },
                { "es-AR", "1723597d2ea8302c2fa14e38b3c8643749e736fc1b39a70688d089ed4c9a7b1a1a2a10524c8e12841fb4bca805d50043415184572904e764a08c5c6842cf1d21" },
                { "es-CL", "85efc3521deffa09c9e29d6078daef7d47563f5edb41376a3e35f0025e81c27685325954e9b70c3abebf76b4e5c434d9597a9c9ed3cc8bb8d8ffc526515e6013" },
                { "es-ES", "2723553057093876fa1f31837e58e1829e18f5a67cbe96c69fe5b96073dd27b86e768a29fb4d6c515681d3eeadd956c4a60c7346f7b1041e357503822965306f" },
                { "es-MX", "3cba3aec072f41bdb6cab09c52eba060ea28cf72c714da9bb083bd7ae2053bf40a8aaf37c2bdf54b7fcff70261b3bd41bb60fe11366f6765bcba950fa7bfe244" },
                { "et", "d67855c4eec7c2b09751fb3e611e485bf458c2ba08232337a544206129166c4c5d3d2e927e4e9eab5e145a847bb882e29013cdd3a3a80dfca0651b672173b3c5" },
                { "eu", "aca4043dc9f74c6317d2b77c3fd62c4b0b9ab6e2203c1359a03deb26a14e3adda20df36aaff4d778ca3b986e516f719d99aba2aec2b891e29bc5d3a4da71d86e" },
                { "fa", "4aa2d3f041ae77cd58bae012cc7fa0b65f99d4528033e48bb86081539ae73df90fc4823528b228a56a373559b4c2961d06fa531b42628952a140dc58319215a7" },
                { "ff", "ad484828dca30c5fad725758d177464fb6d9bd5b54b2562ada16f7a3958983a0dd621300a0223f4be2bb875365f84000e47d33ab9ea601a66e4e88ece764969c" },
                { "fi", "2dafad6fc06740ad11b2b155f3e61e0673e17d84f58a819347afe9268bc61c66a4ea37637caa4b4f311abc93bdcee992ce88aa37c0d1a7459685805090eff77d" },
                { "fr", "afbaddbc8796fc056ee8b2be6353a40ded232edf17adba4075fa84b6bb8ddf756498351cd44d78d75da833c23a49da84343d6a9c8e33b291f97a7d451b3ba6a6" },
                { "fur", "6ee057b649776ff84f7702e5f0a5ad83bc8311436ea844c6b5cf473e51ba84a09bda15350e87e17f4d8383d7f23ea3cfa36e98dd37aaed7014eb37b14daff10d" },
                { "fy-NL", "05e7363a3a692e6630918b5b2e50518d6f5c081106b60e606e99cb205fe680d8267e957b203e4bd967629481b177037b785998b9cb5b92d027bf36942c784366" },
                { "ga-IE", "3e071ef5b584d90f00b1c56c82756ac9e2883560def7cbdfa87de226243d39bf0b10460963d15049b4f3f87655422fa5e7f50b155cfaceae5d96aa6424ecfced" },
                { "gd", "2d886ee4eea74c556ff5c0f6b63d8e3d672adbc716810044cc32a9076f54683cb4b4bae0b92010979d5a61b675b7172fd0b48f190c440dc0f3ed87fc3de2c045" },
                { "gl", "21c8820e93d4575b4c6664343bd0530c35657157881a1c434e5a26c3c15bbdf92edc0c668d8bf3231eaa4eff2683d2a53c4fbf434e93c0d100970a3c2060e407" },
                { "gn", "27632b672e4bd58ea332095cf46f751bd6571db17dbbb6aad2d756237962dc1cb61b3f028be9f3d92e1f05f0f00df6bfd00043d157bf6a644359ce4cefd96551" },
                { "gu-IN", "059fb5c0e48b970cb0015279b2d428ad2e8ed67919660500848fb02a1fc1863e6fc385456311e925b568a2134244a45e5540c9cbd96ea7f63c6d1040ea5502ee" },
                { "he", "601012d3d9397e3bdd8a81bd9c8170b2a98cd5cd46933b4bd275cf1564635b7a349948ce30d5119bcffc3ec175e7626e714424ff2e46c71ed08a04a849270924" },
                { "hi-IN", "c2f5dc55e16d6818efc35d06ea9c962127519c19ca6b416dfb884444bde08b3dc39210e34f47d8fb4b37d7a4e2a539a45b9b8adaa457f1188767ff1167eb4eed" },
                { "hr", "6baf8514de51337c31416ab7466378aae526884a962312fb7e1daac74d163ea271faefa57ca136ef81d4d4958f65cbd29fc06be1903d847122c71f48d6ccbdb0" },
                { "hsb", "25b3a7156eadb77fe3fcc582b17408861106eab51f70245e205085dc5c4cd528b410a169186446504e53c8ddd93aa4cd03252a12fd74d143f971ccda3e69bb73" },
                { "hu", "d825dcb08c7a6481ed297c0f7a399907b2754582de99c497011ab7e1e4e1c4e348e656e3fbca3dd7962ad90a9c36aac6d3794160e85e3d7a5bf6976bd75fba93" },
                { "hy-AM", "71f1fc3831d341ecd396c22db81ed9c4a9e02fddce769d64d1487101e17f725d751228273779d3019d2939a745f069d1f17c2b588dbf4d883026348e5aea1ddc" },
                { "ia", "7a8562a4330ee4ec5640fbe75853ed250e01d0992f0ee09ced038b52d33853d7cfa25eddb7096c329c8896d7416eeda463cabf7fad0526ceee35b792756d454b" },
                { "id", "3a440ab745da2bb041b17fcb07e4860bea730184ee04ad9d9273e64d4061b64a29331d0a03d7c7c78b88f3fd96337e071f79c179e1191530e854911eaa46d423" },
                { "is", "400f7a276e7b509bf89e6b6ec9d939cfb4ebdca461f036ed882a61d025f59173ae05f6d988a56cbac07772e73bca1ff6b0aeb67327f3c0891e5e6d9a6513015c" },
                { "it", "285ca16dd131af2cd98e755168bbccedbabeedb409c09cf8a201e97d043c4b299a6facbaa22f1c33a34846b93bf2f357f5b1db54b84625e373a900452b2b4c56" },
                { "ja", "c5f7e10b13a8ff8bdb5f70cd95e368e2b058e9a509763dad0593377deb69fe05f1c15f2a2741b7e411df2c991ac95fc3ad4e64f7cf6dc7fbc2914653e9f2ea38" },
                { "ka", "9f37365b132d3782ca122efd275cc6fe9c6c0438bab4a17224be0b7f25eff6a4ce334930667d193dfd81522a4b6123e9b5c2c8e326e739fbddc55889d38430ee" },
                { "kab", "438c57255d479f8a0fefaa13ecb5754476843354edde354e8a961c93f7a2ef74cedb63ce84d95edcbc484e90def3f1300357a1676c47e89ba60fa0262d2742a4" },
                { "kk", "017a1eb034cd05db5576465af80dbbf28572f7d92346ba566db2b9ad225e274c01ee7731f9245068d165356e13892f1f24caae47ba163480032f017cf62d07d6" },
                { "km", "4f23abf6bb6c70c2f93ed1e2f45014a29e95cbbfd71b779b342118e83d76681ecbf2c9cef133dc7dcdcd089fa810d26ac3f1934bef4c18e7104385b07fe86a7b" },
                { "kn", "270abe6496174ea67bf48e1acc3b9ec114c8aec9622ac45986e165507e11aac26941875fef844d8c1dc180622325ce117287ab5ce635eeb5c88022de0dff2087" },
                { "ko", "5e6038a0ff75a634874d35a9f9cbc81ad52ade0ae1ebc5545a23ba3db514e2db6f8e7d369686ccd5e73cd31e6038ec48311b57e6f7bc611f52d034d92d94ba0d" },
                { "lij", "6eecbdcc754f2606c6ed16b47e13f1c039d6141f6b60b28757943c33a28f2b60107e2623fc16643b592912a856c8ed93a1bb471ae1c32184fd2ddb1bce524ea6" },
                { "lt", "69f227713e7d289556c91d5a0f06de133a8e902da7c536a3603c1efcf6ed5f014a31ee4e1a153ea34cb7d2656320dd96dbadb4557b0200aa55bf538ef394b538" },
                { "lv", "c2b4b46a4ce09916fe98ad4980ad0fad0d4cf28b27df7725c6ed048ab874f37ce0b1953946462c08a1e35b69b070c9f4810f421fd881a2ba49a3e9f194d3fa82" },
                { "mk", "6295fcfe8231a6126c931434cc05da1371442d5cba1ea8e8e6d77081fce8168434b3275fd427eccd63e4a0465a87090a2f790e4cbc9aa199d2e1826089889cb5" },
                { "mr", "2fa1884661352e4a901356a28468409be624724f41da397284f5de08db80e9b5450a99e7d2885f9576ed6728f248fceb9d1ad09a6228164d1b7c4ccf0ad2b8e0" },
                { "ms", "f284444156ea746f9cfc5054936fca061e7554bb27271bee457889b331c0056f2cbb355db9d3fed33277d0eeb00d1609f1bef37a281459620c0acf61e670af79" },
                { "my", "4b0aae9f0e941b4d620a451851cb5bf00f63ef9de398fde8d116ed9b6e861f7757e57b355d209ab7dad56cc96ed66c0af98413db571ab19fe41e7d6e1b58070f" },
                { "nb-NO", "dc8bc3d32b8a57a9319f05d1f1623da350596ff86f3c1d16c4962696b6ae3709d480d73c7a6f72d0e1a835bd2ae68aaa6b21861e87c6041b10030dbaf4a91ee5" },
                { "ne-NP", "624dfae0d5ec80aefac8aab85c290103a36235fc66ea38bff7c2b2953cdd4dcb86af010c105f78b156076fbe5d889eacf498fb1c3444adf5b28dfe1b3419197d" },
                { "nl", "175036a2ce14ce9f36ae26d85273c3b8cc5b29c88454ce023d077e87a5a937e3fe3f591c6c95524d036c20f45c2cc01367fcfdbfa0e71f5f11ddebbdb6d7c447" },
                { "nn-NO", "09bbd8ffa9c42eb4752849675bcf5c70445ad35358003a5e3c963e21c659c8c0853527ae8cf3ea365a5b9f1e488619c54986f878a0a2bc8e9d7c44984f2864d6" },
                { "oc", "1309c670bc7bd4696ba111028bdca1b11472afa7f901893454eaa8306ee561d858f65b34d2a3297cbc02d06ebfa0b6da9872921dbbfefbaaa14e42332208491b" },
                { "pa-IN", "693f3f2f0d6a8434d82a3cb12c8594752859e2af2394fec3c2e8a4dddcfaaddb89f1a0373f4f3b8e2b8b51970ce0a000a7dae1be3b3e6832bedd4cd7f853fd55" },
                { "pl", "77628fe339e8faf09437ada077b74b6599ba4873ba6d3bc44583aaa138caa321fe137c8e8dba0be1e1b5a793edc25a633d98c4e150a92493e0b9e00507657ccd" },
                { "pt-BR", "ca2f128d611af514194b89b55271cbdbef8b009f96c3ffd302bb649ed5d74dc4b996b6067046060eeec5a8368aeb59712d1defd467e579dd056321721a8f9be1" },
                { "pt-PT", "b48206c70b240af6c7f1f6870b60d8dae2ffd84fd57d177f591a0a063268a0dffae0cd02793c79f841b0ca7b21185e92dd7727f501e0a1e48a1f7405fe148fdf" },
                { "rm", "2bfedcda2635c238b61684380d259e0827236d3b41d2fce29571c79faf041fa615d6ce02c8c4fdde60a5d3d5b36439172836195d0f21fdfd77ed40e4b4d0a68a" },
                { "ro", "4ed480d222bf038d2980e7a0fc29506865a7a83690464cc2b758732da72abdc6969cdde43ccfcf6d9de3a2f8ed9c2b83bcadccaf4d6602e1ac8bf695d93470d6" },
                { "ru", "8989aa02d77b480c028f7a71a8555955934fa0f257799282a81e44f2d06f0c6d2dbbe76f556a45093d8ede4b76d40115ca8723407a5a55921a57cd727774d253" },
                { "sc", "c007279177fae8d03a6ad79c429edd9cdddd9d9f3546930beb564baecca1470ee9166a452f99285a39e0c45260014f1465ead2609c3adfa5031907d048cde9d0" },
                { "sco", "aa26eb7da589279f08e3834c46132821cfe20d4c80073e460722ce0fa3537a386106ba70e563ea5b337099166ec66faa3dadc96fd983100fda09200ab98db0d0" },
                { "si", "6f6473e94278b50eae49ddd6a93fc48f47179b6578d54adfd7534e68c4c7b80bbd70039952705810688c5a66290199357dc2b284d154125f146ed3405183f760" },
                { "sk", "a3064ada07220fb9842a87b1fea27b135b3abbad62919f7cc881d4fae6ee5cdd3d50d1ab69519f2c700773fea2bd286895991b26cc5ce6dafe8aaf629649b3cf" },
                { "sl", "5ef343c36eefc39a49ef3567dca5332b2caf7151ffdd2facbb591f3214ad8a56b3ca31ed04d133776552f8fc53feb24a3d2ce8568a13bb9614c12640ad403898" },
                { "son", "3fc38b350e14038d0e97b4a368b915e00fe0363889083a3551298917f787d21b5de0a1dc20394cc99741bfa234202170d9adc12d8c71a235d85b0991def16659" },
                { "sq", "ba21d10bbb094259abc7753fee3753832dce2671c3f8bd062daf4f92b0f7272730b7ab5005aae3d135e0add1255119cacd8dfd7866fb921cf8f70b84d47cbf4f" },
                { "sr", "a759e6799e5e1d6229643893854a468fd92ac3bac7c659c0df080ee52defb03a80f18633b447225501620823341df8607b4aa94d45cbcde178056b32da55f276" },
                { "sv-SE", "1f75d81cfaebec55f82ee8b513d04e8121ac3878d74a30a505dd99978589cfc5f86e3e437b310ffcca2a8b759999fcdf4d61bc575c0eb4f2b948e00f919c1c4c" },
                { "szl", "e0e1acefca4002957f0754713f8e618da623068ed41743d39cea44f243c22d932469bb10b8a2f1929c9843298fd3bc13eebbccde01ee4bd77295b327a2833372" },
                { "ta", "f96a0e72da7162317bb809da624bc82b06ecb7ef8a7a862b63b803bbb35e7e3f152ee32a0a64e45085be3c242b337dc09c4cb958384f90edb80bcf3bbec8cc03" },
                { "te", "3187c4c796b43309ad619cf9cc43e8c84943fc0bec78a1027f29e44df53f1cddfb0eb4685865605475342fa92bc6a2b088bdb727e754f773e9f07ee8279fb818" },
                { "tg", "e26f0f1c70502867bb0c476fd948c978b7107214bda4d642901a4379041d81737cb35be14b17cd7cd3193ecbf7738a72a5d29c5aca9f553b6a038482e2eae1e0" },
                { "th", "54ce3c84b34d6194e5245b7a875230287896bba813b2899b231ef935b742ada1957878e23a92f147dd8dedb7a1d379a9f237f11eacb8e8d02e8ee3ee300d0bbe" },
                { "tl", "8e0f8aade2d2f63f500ccbc9bbbf404f005b063e2579c54e9f9d8fe9ef67ea6a8ca7f14e9145b84b7766ce5cb4b5a2ab2ec437302a71900718f7e7a65898e9e8" },
                { "tr", "5f7120ccfe643275ef6259a98cff24ef955c6abdd210f7cec13be77deccaca1ca7287b1a0aafff58040e5ec0a3e414910c7557d54b43af1c9c41b109d9ce3a2c" },
                { "trs", "35a99af3320fa03246242633ef74ea42895623524e788c5a3d485169dba85f07c093093f0ca89491407295e409f4d960e1b681f630341a05643e3782e0656fe0" },
                { "uk", "e360ba1728bb82e72830e16031e4928f6396c21547c4199c28e1adcd30de28c98df7b46ef6e4a332a1f6dfda4780670892eaa417e34aab4565cdbda4b5bcc682" },
                { "ur", "323827b3475190de1417d72ee92270680b907a46f8ba9eb2e222beb1898e400ca8190c7aa51c52a09ec1a1a4e2f9787ef15bb56f0faf3c07444517abfc5ee2b6" },
                { "uz", "3c0e114753605fd3e4502412573eaac101b3e26819eb35c5a89b5153046a1a842cc0b448d58d85e7c913cf28ffeaf73f61942af64809091fb85b3ad77b9969ee" },
                { "vi", "b9c969b6e27974340ef31d9ba70e3ca446deccc54342e89c4ecf865555f0946a9f6417baf43fc80e761ddce4d7d0011a4831a0d238f5faa5139f63c1f7486a01" },
                { "xh", "9f0fb5373f6bf1322043e807ecd7abff99d9a8b2d9e2bc80f35fc2e1861dec0cd71ace4aebc6eb5fa6a55f0a85089748ba2181c2558f6cfdda0253ed1a3c1e00" },
                { "zh-CN", "5081418021eb1f776f2b935b655773b42acd1b45f4648ada2c7b4409a6f9d86c6a7a4bbab681ea870b03dd0cc04db3d4181434cb398ce35baa83ad72ec3e5514" },
                { "zh-TW", "b18b82fa3e34c01c9464334840fdeea6304c40cb653650cf7ebcbf4721ff99345ecf12a7e2814ab1bb7bf662eae51f624e71d96011482211022ec262ddc5c343" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/115.5.6esr/SHA512SUMS
            return new Dictionary<string, string>(100)
            {
                { "ach", "eb0120c099221602d46fe7711b630d0ded8efeaa8122cb2eb72bce3ca85f433f554a0d52c33bff59294bcf6f88ad15024e681ca7e70a4dd3a360d3cd298145e7" },
                { "af", "2f67c3de1db3fd940c0d9b3c744528f3c5268fd6a2eb3273997836d0b37509f7ba8b8bbfdb5b72bfc846c0ecbc24fd38b0262ec45ea7749e5fb1f12b9ff0d519" },
                { "an", "e4eab9b2120df4eccd20d1905737541b247fd198c02c8eef046ced401ae227529e25588141631f87233cd5b412e253c45f521c593a343dfd038bf77ff3abb8a8" },
                { "ar", "bf3a6b99f86bb7bf417823a94ffc324dd61207f7935fe4d65add1d6d76dc6a032e45bf15992a42c0fdd860098db92b0443121cc2448966036a2f8b3885b8fd3e" },
                { "ast", "a9dfca2fc72b4b75e963f0da57d02f25e63c10b977da01abea3a8ca85dd3e5aa0d2b30ceef2367782938f58bfe04719133c39a6cebf6e04697faae2e8ed70380" },
                { "az", "f0e38abf1ab1c162abbebc2fb504890cdd714c0f1598372de8d4a67949a3da606a626ae7e6b01075ccf4242bc7993a564a83ac5c481c337b93645f417bd40f36" },
                { "be", "cb427be182fa6cb72e6f600d8c8b9c6f89b9f7ad94ab7e7399e1f368b806341517511c1aaed599d6ecf52fa4b05dd7cb1e42c535cf96e126fa3e0b864f61d94f" },
                { "bg", "ceef3f4198fa6d557c801b06cba925ff166c2b2564db6d89f0586ccb71d4390af3ae51aa249e59408e30f687e7e289f5ac12f23cf631a9b49aee7e09f940a40e" },
                { "bn", "b62f8b2573b2c96e2e2675610a62f3d246a099b5f0c76cb0d7b0453a6b0669289b9d5a22c5710f8b28cca63dca0e47b3f6f83230033cc882cbefa1a9ce359ad4" },
                { "br", "34de532e0d0d24bbba898ac592a6df5018181acd5b8ac50a5ee0bd0c945c8c417393f71a1dd89d6d7ae0fc4743833e1c362c487bbb45c8b0cd7e10898f37d98d" },
                { "bs", "acbff8a8e5a215e0860be311ee68869e52190f23cd78bbb0838f1b5113f24a31fbed56b170450e9babe4862fd462f4e708eb118da08342b1339d8a9777df10f1" },
                { "ca", "e4fe3c96b9d01d19426a848669a612a2ef84e980012713630b436c9cb852e7eca34e3f9f2dd09a3aca8c7f8f54c87bb4a7f1e36bc7103be74d41d157d0b7a978" },
                { "cak", "4882828300af229190ef868425bb1a40339c4e2912be7b278fe939f51a3af6eb52e7889811a25ae29c6403ee0ddeb4bdb009a3ba5341edbd79ef2aa689605a6b" },
                { "cs", "600924a6388595d40d3d6a1565ecea86b1ec6727eba62b3442fa9ce8dab3627b93beb3bebd50017e79655056ba9807f92bd13f1c27e14932a7f72e96fb7083f9" },
                { "cy", "3c866f08c8946b1413e7a61e105d8d9f8ccefa6b24f38641cbef188b5bb2133a5edcbbb40e13aa35460c22bc02e418d16cf419dd779e8c2492ff79c5816b479e" },
                { "da", "5d6994460f9969ecebd7358616aa180e7511f46c4faf83aae6146469f77ee054bdb3550460ab51a0dbd419e43ee09efce022246354526d57706877073ca6616a" },
                { "de", "cb0d4f93a4121fa0cecaa442b0b78534f5942c49d70b61c927cb63620027f381f1a3a1ddbb67ffb1c7236df6a21b045b49caef9acde6ab18143ac21313f49c02" },
                { "dsb", "78cea62b5ab38b9b137dd75f2c47e63d26834a883b9567328c35af9d3218d2c6d17f72eb898c7c3a2e88252a21cda92cbeea190eef625478d4f54e3375f336c0" },
                { "el", "54fbead3aa39c2e86b51f6718e51842ba10ed2ff283dc7cb9cd0aa44944ea17c0c8524201b3fc485417a02db20dadd253c34ee697bbe1d31e08feac91ff040da" },
                { "en-CA", "cb8bb1b42546d1c4e6dce957d7441cd28bb57ad57c3f3ddc32d514ad11ccdaad61629dacf85fe8a1f01930eff4e65012cfd45f27236ec2ea6dcc7dba0d2ba6a2" },
                { "en-GB", "d8749a5d4a30f9641fd43e760462f21552966698b9b7fd8f1e40dfc37a931238403433e25f153b1fb45c8086478204f85ed7110b77f62e235834510aa2ab4633" },
                { "en-US", "1add8bd9e1fcd6c08e75ace2ad20d7307cd4f85eb717f4c2f20a53251d138dc488b33f8da450aab24a1ac9b2e5b372138a9d80ddcb57c58dbd8a5392cccff548" },
                { "eo", "a90cb45d985177c4921a2910f711f93b6d19a16a00c5c535297a35ed9e54082a0d8c728ec88e83c34bc5aff7cd9224cff202d6b7a185d1d0bfde21ff1a02d04f" },
                { "es-AR", "94a6e25517c01a18b9227b24b89c1e7d720c452a65640a187aa966e198f5776695feddf2259f5a7fc0f2baad0f26e7374eb7141cb162366aeb27ab75dcf5f76b" },
                { "es-CL", "cdd27bf23032634f1ca4b306886f23a44389f16278380baf007171d58334eca47597b9e6dad75c602f6cd81d49d07fc492014697fe001af7cabb2d0fa91fef7e" },
                { "es-ES", "897d453350ac60706ec9fcb99aa03ef6f3a5b36bdc496ac9c72fbd898413a393d2e5a1e8677fc79de33a09af51eebdc1d14f74400ec8291cfa215352c13618ee" },
                { "es-MX", "c345f28c2f6adf85132e5daa64f133086653aa5b7562e7dce9cf9593dd275e727b6fdce6f81ee56c5e277af0c4728c8fff4ca51a1ece1e103322c43e257fedac" },
                { "et", "8a84a528f3c93008ea56251b2cbf7c038e6bf0d1c426d9574cf548e2450f4470b38ce60d7ab01c4c61e495d0bda5601c418d70bc399e159a5a1129f8dba354fd" },
                { "eu", "2b7b6607cf29dcd587db86150a046d94598b0f52eb5446ed5dbefb73c2be44a4078f5a18577b8512181282fd496ac817a589d1072a650e57f794862d56c45bc0" },
                { "fa", "9716373e55e2b018fe9a1e009b99203ede207e6707565541526632e55b4fd1c2aca5f8b9469bb8d613dc504f666df0039e3f6737f232c65bda7c7438b25e3dea" },
                { "ff", "c8d2ceadf826025e2c28de8450b18beb1dd42c24e0b86e40698fdd342a276c0adbe12616861c59512f8161c59e3aeeeb0482e33c94eb7bcc232269f2961bc68d" },
                { "fi", "ceb9be5020985e570cde04cac005c3da5df581c08345ab608f05dcaacda808a759c3bf88fd69bd64f3a7960dc645701d8293afa929e14131cc8976b433be1a79" },
                { "fr", "a7cb8b473f13a1d6d4673640f5701a87fd3a4e8c3e2bf9a3216734c688230b3dc6d7f1eef164478b4c529d412df42d046f18ab6a8950a8c3f81a88b02b67911b" },
                { "fur", "ad1ad693ecb5b29607d6d38fc8c20b798ddfcd7b33c475a166b42a17159d7d07f3b5530fd8628505ae1c43e08dae36535be761dcea1fe502725194b2e19e9f2d" },
                { "fy-NL", "9f84ae0e514a3edb29e10913cb13997bb91fe51f77743d8e919b98a9e819e57010dcc3b878c1fe5ed650ac69f58acc7564590d639c1728e8e1f3e8d03a4aae4c" },
                { "ga-IE", "ec93e3f3785088df26bc0f9e8fb3929cac9fbbb5a5afa10f65f7087ca44d79f9fe3cdcc2c242765f0ccbfe82dc06f054898405765594959b0984d3372bc398f8" },
                { "gd", "086528698c45d7853ea0a22fca140e97cb48eefa76f880c70501d07a31a68fd8805ce98031744832d6e7bd8a365c63335c70cc95b5006768e5017c4bf0ceb73c" },
                { "gl", "86e4ad51702d31275a6b4a9af5b08bda724ea720c3fd93c1d79d6f1e62bf8f1fd64be12598230c3394226b0af8c21a577c46f5ead0677cc69f6108515f7c77c2" },
                { "gn", "c1b401336193138c6cebbb28301ba58c81f5688f18eec4a45f70d7830d3d5a750b19a6cfbffb4f0ff7358c6ef704161d58040e48e6f2390c6e16098559836ddb" },
                { "gu-IN", "6aecfb0e235a1d1a351c87559762271fff194ac245cb153c4cfc2dec7aca5dfdfc9ccdff0eb7c53a52ac786d75a495ef3d3664202ecdbd871e6ef5906ffbf08e" },
                { "he", "f47fa7d2f17fed761c8906cead1831d64de082a81f46c1a6a9854cdc55d83e50e1ff7516e14df3261d2781e430b206c7e8a34833fd22cfb29576eb23d3c44e6e" },
                { "hi-IN", "d147ce3394450762e348dcace9a401c5ec400e78493b50951adc0d10cf8985d46759a2516a23875023e668fc8e4ddcecf345dc46d2d84d9974bbdfbef6de8cfa" },
                { "hr", "3d347e2b481cba899191d26d64d5300ce973823a9d50ec51d85d02edcb6ff973cde2b2842320f042f40e8caf9e710971c17caaace62d158fd2b22169a9080664" },
                { "hsb", "f241dabf56f378d218786f500c5dda7f4aaf155467279955af021b4bfd61bd3c92966f9d285cbe396851751094288c75f0c68eb94fb2c15cd6bd170fba93d91b" },
                { "hu", "47c4a241808f586c2a18aec3deddab28f2bdef8a07c2647b4d639608375ab58c25bc80ec767565bab934bfc9d7e07cc804547aac5ecac6f0e4a52a852df8fa9c" },
                { "hy-AM", "714a91a40430976d3f3ee6c18a86f29292aaa6c07f74a89ce570ff30d205bc762fb445535b972d9c3bb95222a39787e2f4bf057b1bc6f6d3855bbee15775a00d" },
                { "ia", "fb07307c9bfb82d6187fd867ef27773c993c9c6f281756c7a7f956f51ad33f95e43b01d379a9aa81c9a245087d7663ff9cc685e198028d5f9dbc0d8f03224859" },
                { "id", "b0c67f57844f743c0b88a8a8595441760320dffdf75c0acf02472953d02324760660a32f427bc652b1c3bade5061718bf89a3868f001c5b4e5319bd788ef2340" },
                { "is", "dad3e0b57036583260ef0880042d83bf846f42c13ac1611edfd9a35f985430f6faac06853d4c78069b424f101d0b301ed897a9822cce00556bf7a8def466bac5" },
                { "it", "db5ff728fb28767365c2f8370b6892f2902984239c5ad1abae4cd81e77f1c054740d83264fcc07039b0281babba6e692fbd16ba96436ea8697f8a3ac1fd1fd16" },
                { "ja", "5008c9c01f96ffc71e87848eb558ae870438d66f2a3f8c67196d6d5660b728281a196d7c043d8abfdbc7886e07e786a86f418ec95b1039ddfb6c73b2d9b61271" },
                { "ka", "d1b10656c5bf80dd0a098ac44a511ff165887fb506a7344d068e77f60041b4008832c99c6a85613daed8a81de7e8f6140c16a3e55457f2a38ea5c4aef9b61177" },
                { "kab", "140b66c15b0795781334a28d3fefb386c5a51b60803327845f49a1a3026a310c53acf2779bf20562fd92a9a59c51902460a5e94605d223a4f8d1a258ebbf93b1" },
                { "kk", "8a823aaff58150e13d8992c951f818373380065817e14f8c6631dc2b7f2259d90a2b5809e70b33e1c21f61920e1185f70c0af45e514aff30473410681c83dfa8" },
                { "km", "6d453a57ce430e762d789deb290256d5f513fd7f71211244f07b8526bbaf0f5e27fdb0066e33b4381cfda38abf1547c816e092fad760cf9741d927c063aede45" },
                { "kn", "39153f1ff953c00c8b14de9cda3f666aa728c742216168e71b3b370b2a322e5fd637b5bb99ddb1c63ffef426f4e43838ef234abf4ff956c6c6f41a46e4152caa" },
                { "ko", "71436a1d460e6a1da0a97079797eb11c233c421acb01558c75973064e9af320a52a0634cdbd387441872552239b0c85d9a0188241ce759b91b471eef82de0a65" },
                { "lij", "e467f3de455392323476d9580824ab643de7ebd89b80f9ab191ba3e710a305ceb78139c1b79696336c7e01dfead631a6a500e6334d31273499b16cb1ed6c4abf" },
                { "lt", "f42d67b4ad347bcd96fddebc2962a7d1886677c6b11844d7cec28f408dce6d03e28fc5ac9e50954b9ebf4cab6da6e9dbbfcdef0faf578a66040fedeaea442db6" },
                { "lv", "d7c841103020e0c98705d84cff68152e1945ac338fc73eb1aeccbaa51c3ee0d3037daa72274145bd624582ec063651bf863c3015aa766462d7ff7656f4669466" },
                { "mk", "0e94ee23e980666726b559b40d42f3e66a5db815f421db4ebf9502fbfff2457215468259b8396bf9095d78dcecbf08011dd5768f429490b2b62439a23585c499" },
                { "mr", "51c336007b2fee4821692f8e853abca35012936a0d304db5d1b5e575ed047c08d5e05b099a7a4ed587f43903af77c8fea2d6302c2a56eec41b72ade8431dbdd8" },
                { "ms", "2da11467d4b9bd76ae6f35bb7c699af11a087966d093769902e6d32d3d7f04154433cc6ac872c82208a4edca5fa926af175d4ea9bf8f9b2f035b086e1310a42e" },
                { "my", "ecdfeca11b22e1c4b22fa1c23e0689184b2612f5a3771ac7798206625131a6acdf7981a5c11ef502bc1eaa665d1c2273847e21931d4dafa230366b523f958c39" },
                { "nb-NO", "1987f726566cc07ff14571c91eccae3354788a53e3c60832170a66a592640ff999438e829aeb9c11330aa01a9bbfbde259dca46542979018b658c120fe514fdb" },
                { "ne-NP", "1c46ffb9704514364f378913192ef6448f9f8aae687441deb3a17168d37fa235dc6992bd90903429096d6375ca41e5d5198da20e25770c44bc8f4953cc12ec6f" },
                { "nl", "c31963d033080a33a780945a083e17c48c08a1c19f5afb41c6400be7664f68338487c6f5c29307482ab5edc5895ea382c9dcbff86d076d5eefb95bb82d2d37eb" },
                { "nn-NO", "9151aa5018d515c6791c9d3a51dd3feaa4e7563bbd3f841d1c380c6caf9ef2f84ea449edf5750f5878a047f8184bacd6ccb31ffe41f9959abc32bd5130738bf7" },
                { "oc", "701c24f0ca31250f3072ff84b2c940e1e56390aae9e76907f439ecd18496635788142ed917f2f5513f34836037776ddc32f05ff88f01d667301e8471b9eacd8e" },
                { "pa-IN", "bb67af6584fe2bc381401e68570eb13d9a9caea1009713ff1d09922a96e1289354f1236563ca1bc26f91959be6d391f36a5d6bd5818e70dff3f537a1f21847b9" },
                { "pl", "7ea4eaf7b1a8ef94ff211c9d59dd4d7ba95b38522b5e03183e23861329a0bb2844d8de1480b1dec194dfd3fa896722fd1d9305a178230b4fdcc074788c38e7d8" },
                { "pt-BR", "98ae43d23aff1ff19e64ead39a54a359d0b693b418bde43f48c9f094b15f2c07779778a3cc2073b11fdd9708d9ec3548e89e77cfec5aef2a653aceac2f4208bf" },
                { "pt-PT", "9b6f98bde03aab87ecb2afd0ad1d459c6bc699f684eab7df9fd6c620abe0be52253315a64c87d54bb78a5abe38925fff00aa6050468011a93964a5bfda1d9d26" },
                { "rm", "5299250192c9e84cc0b2d9d3dd78b1f2b72ffe5b7b3986f486ea9fb895f3933f86ac165d1b288529d8d1e3b195100d3e3f43732fd3456cfb605b10a7ac0bc517" },
                { "ro", "6aa3dcbfcf6ca5004523d4cdfc596b908691a62c2fc81bd00dc04edaa6ac21844daadfa5ee571b3fd1c8fb88f34f0e3cfcd6ea5b3cce088996d4bd8da970d0b8" },
                { "ru", "b69106db37c5d6ca7524a3cd5af8113306c168eb55b33b2f7732cba493396dd201990d5d5b52f81d237696876efbd39f07d546d16e4713baad69d46821923e72" },
                { "sc", "b07381b95a8603c50f5b571a397de1c5388264d77433866daa3dc5555c8612cbefce8bf1739ecf11ac0f22065d258d1b9ea5af89e3866c45981045f11e796795" },
                { "sco", "ec6a9b761c92e67df509d146d42e936d273f0c78fffc04f187b772176ab57424915808d21fc4eca3bfc41dd96fd386dcd5c15eabf46c86ffd6381cb719285100" },
                { "si", "e2ef855dd44f792ee2a53e2168e72fa1544ac17c84b364e37f7abd6ca2ff5ebab7b45d3a94e9d2180eb28dc51107e505800491d99d2d8f8ff725ac7ea60032f7" },
                { "sk", "4d383cc73d34544176263c8d29df04abc7a16ee3f8b0fdd32e6746a39ab8e9fe0bc63452bb0ec578caa19faac6ed8f5ae771d36105b1742a4656cb64da2b83bc" },
                { "sl", "8f27c6d249f41f05fc2e23ce3ac42e0d2cd1a6b51a4e47c31e580dc179b88a208c2be3e70c1ebe8583fb39eb21758bd655b236c262a656a50066e3ebba82b912" },
                { "son", "0d213c9c078cd5c2aa1d688456bc219f3f337fa36bbc3e2afaa97bd56402b0f3db6632276075af61d1556ee6eab1f4de4e0100bd26697a14e700967685914613" },
                { "sq", "64ea9177fcd95ba3b936d89c2031308976ecf601283dcb82564189d84dddcd35f75161790c5e502e1f8742cdfa0bf5613327eb4c2455af8dbe3ee438ad9baf39" },
                { "sr", "5ddd33886e32c692a1487e3e2d77b2f6899d0a7031061acce6bb69dce29315331a6f91626e2bf73740652ca5a583b973b4b276535000fb358f8f518870d72b8e" },
                { "sv-SE", "cd85240665c14f21a69fe187c31d85a7327729bb1e67f117206ea95287693168aa78c7d208b85aecfc1a117654f6f719dab14feec0a0a958e5663e0fff79078a" },
                { "szl", "43198524b2b6379a460958f4947d934627aa99620218a31f92e65bc79900d54fb7645134ffdd84d31dcdd06aa8ba0aeb68ab921a03629cd32038f676e08ba29f" },
                { "ta", "9b624d7e02762c2c060f9a57f80c48c1940e957e0e867a6f74e850c35506b72d7379948b965dbadbb369bd556ed0e311e85d6406094e7915ab7029b5e8b117a1" },
                { "te", "24685c35c3d6e09be2c86a360396f9160f716046fab8ff1b41afca122a193529c4853c8934d3d6ebed6381c549f65c96d18becd6075993dfe2ebf4b50810f4e8" },
                { "tg", "9c84e1a31d8462609562303e50a9b93df9c2d68a4c369c733491ca86ff2293c380b216cf515c07d192a9f6ba93375da160052ba1e887ef2f454a23b49a92f5b5" },
                { "th", "4b3e897129dc7b0e69e4023f33dba6dc920a1d5791be1ebd5fd23b66ea55de344a716533087d36381f743af4556a8094874315a6f83d07f24d5fe2a744c70eb1" },
                { "tl", "fe34c501908d579111a40faa05eb0897c7bfa6380fbe6093365f5b37206cf343b424f3b4b162e1f4c93fd0f3261fc42d8cbb6dc4d6db1d8ae4baae48b7ca7fe8" },
                { "tr", "649d9a1afff84a19d9a387151e3f621282970169787b67132f52be8b7af34957c8257f86a0e7e5e1f2947720755f16db3b1e7e7e57dafac20367ed43352097dc" },
                { "trs", "93bf0fc5fbea40b0ecee8a7b90bb505de1156446fa3df23cf4b678e3ae0a217b0f6a621bc2c5d33d550aa67dc130cb302f0bd2519692f4330a85a111b27521c0" },
                { "uk", "3cd56383586a3af310899e822dfffdf3169defd9ce3eae7e46986acef3fb03092be94edd897040e49447a2e3c1cf113c8a8ce981bef5a7cd233c5983a9f616c2" },
                { "ur", "821f79d30c069f1f0357e79b510e384ab94bc9c2ef8fea13c845542894b7bc9472c2fd8b71ec4e9eca67ec2c50129a19f169012d510aead62764f0d5286162ab" },
                { "uz", "c4102965fefc170adbd10330c0bf259a9288c2ceb93afdab88ffb1795617f9e652b91fcbc55b0577ff4bc319ce36391e93ddd09ab1a6b8599f7e93ccae7875a4" },
                { "vi", "9a0e9a2185c223fe67a8ee2190eaa37d046ad38484b07af04ab3cefea288109d156310c76ad8edb3a0c11ce105ce8b14650ac84bb1d897d0106d39886b71af6b" },
                { "xh", "24e696b088162d2dddc5c0f5d4e357be73220d88b7d0e234ba46dba5f72753713aa65ce7f238280a044008793bc6983355c553113acd99fa7cdf80e88c608edf" },
                { "zh-CN", "0aee17186b8ba20db87dade631c03a7fedb71faaf3305e41fa23c153548d2fdf6b871d1ca3facba38d916235c04270512205837e4945c0eb59e09313c730017b" },
                { "zh-TW", "43eeeab986f55ef060539f1dc8a26672d0b2266a42edb500ea47d17dc3b7bd8a24f5726151e08290c51c39399af7755bde87f7017c12ca55730f1385470ea37f" }
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
            const string knownVersion = "115.6.0";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]+\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "esr/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + "esr.exe",
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
            return new string[] { "firefox-esr", "firefox-esr-" + languageCode.ToLower() };
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox ESR.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-esr-latest&os=win&lang=" + languageCode;
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
                client = null;
                response = null;
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                return matchVersion.Value;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox ESR version: " + ex.Message);
                return null;
            }
        }


        /// <summary>
        /// Tries to get the checksums of the newer version.
        /// </summary>
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
        /// Returns null, if an error occurred.</returns>
        private string[] determineNewestChecksums(string newerVersion)
        {
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            /* Checksums are found in a file like
             * https://ftp.mozilla.org/pub/firefox/releases/45.7.0esr/SHA512SUMS
             * Common lines look like
             * "a59849ff...6761  win32/en-GB/Firefox Setup 45.7.0esr.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "esr/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                return null;
            }
            // look for line with the correct language code and version for 32 bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128] };
        }


        /// <summary>
        /// Lists names of processes that might block an update, e.g. because
        /// the application cannot be updated while it is running.
        /// </summary>
        /// <param name="detected">currently installed / detected software version</param>
        /// <returns>Returns a list of process names that block the upgrade.</returns>
        public override List<string> blockerProcesses(DetectedSoftware detected)
        {
            // Firefox ESR can be updated, even while it is running, so there
            // is no need to list firefox.exe here.
            return new List<string>();
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
            logger.Info("Searching for newer version of Firefox ESR (" + languageCode + ")...");
            string newerVersion = determineNewestVersion();
            if (string.IsNullOrWhiteSpace(newerVersion))
                return null;
            // If versions match, we can return the current information.
            var currentInfo = knownInfo();
            var newTriple = new versions.Triple(newerVersion);
            var currentTriple = new versions.Triple(currentInfo.newestVersion);
            if (newerVersion == currentInfo.newestVersion || newTriple < currentTriple)
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
        /// language code for the Firefox ESR version
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
