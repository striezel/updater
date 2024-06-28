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
        private const string currentVersion = "128.0b9";

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
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "cbbf8368261200ef7009153712c475abfaa58c7d4e2258c76d642adbf0247b1d3c499cb474c22817c256c8f5ce0c5e799eab3057e94267b8c3f0f2698e75ddc5" },
                { "af", "f87d3725c561e5995b625b665358007cbdcd8caa5e351d13ce44eb20790c6b7bb608f15762447516047fded289cee51cc372e3e4cb486ce79914788f52f6d5a9" },
                { "an", "7a4d4bdc5ce8d9c78c3e30f7180a56320b4a181c54ed2474cc1e0779b4654ef0d82115287d692bd7de61c211345345eeb23c2cb29c38da6465c2c0df20298a8c" },
                { "ar", "846455e2f0299cb3c5530615de53e5f392f25bf025f9b7c3146c2b545bd636c186ca4ebb30b6ffdba76493aac3402ce2eb827d878a78862433189c5432f161c1" },
                { "ast", "932283084b678fe4d6ddfe46bf4decd2a56616b482c0788a04e8bc7b686576627b78f20212c412e9586fd46c2798c45a2a0279b04e7b6774d4f1e3df437b910e" },
                { "az", "f03c58647133bd275354414a9616c33ab8b1c44764fd2682d466df92edb5197418da53e6b764e2a28462588cd44564db6267db168f892f2a93af88603b5e9f7a" },
                { "be", "9557d724d12ecce27ce2f375582d9b739c885353a134973e3f93f8324cf4e769f7046c203d2f51ca5e369106ccfa3e652e6cb5c9fdf6a735d16cb07831f01bd1" },
                { "bg", "045b160502df878ad593e7c816b15643f494e4e119e6255472a7f0b49856c585699e907677e710b461ad3e2c55f3ec0f6766830f0707175484a8378344b4e297" },
                { "bn", "aeb1c507bc11c8c2be859386be758409a9e99805b7796604ef7271c556ac887b44aca2f09bc281839f77fb363faacea6a77befa46d00d6083a92946cf1cea05b" },
                { "br", "a16ae14abd9c39e0212597ac9abcd6202820e57715165c2c384627505e0614d6684866d48e828a7e25e52a834e6d110516ce4bdfc0fe7d7d23beaf1ede3c98a6" },
                { "bs", "bf423c2ff8019ff9c68bb8473dbd6ec0433057555a4087d24bc38f22743d31ac863e59d6440d294c07163dcf8ce28a818c5b40eaf3c9a76e4793566b04dbaf9a" },
                { "ca", "c606cc06d348fc6a1d15206fff9271041373ac2f1ecb11bb275536c57f93506c8ea16d94632373779ba8e894643aabd784650239958a9cc4fb952c5bf4c38079" },
                { "cak", "1db64d5fc6bd95f510e6836d1f0b9f11cbb8c6eb3ecfc90657af2275c53d151ad700426be86ad6ee5576ba6cd7c0bfdd9bc46c4b95719e41d3bc37d171b9492c" },
                { "cs", "1ecc368f6d628c27e348086157ed8695b0ffacb3282490abb3f7c57c357e5c8b7480cad286e07bff18b46725829a100d4d754c7f1ce202f94beec2fd9f1f3eb0" },
                { "cy", "e034a223d1d279a1a0d81f49ac8d556364e57ffea25fa550727ef1106f2da20951b53c9445de17fd6b68bed3ab03938d9a0750e72aca1b53acd28fb58abf7d0b" },
                { "da", "7be1198906e55b5ef7407662fa1e7edcf5e8a6d8d0bab1124a2ca1336c6d05590b6c6f99570d16babdb3646aabed25a64d711a8450ef32d990fbf4ad5c34475b" },
                { "de", "e4ec56989db13964fce3fb1c1a288eea1985af708ebdb29b20b62fa0f0b3c0749c36109e70e7cef1948a87e1dc09ccbb960e96073fa8b7479aafa43d3790165c" },
                { "dsb", "39a72df39f731084215bae1bc4ed04a1e9fdcee39d1b5f2038c8878ab9bb355acdbd9a527532478301f67e7b7d7ded9f28fd04a3fd8897ffc300a46ea151303a" },
                { "el", "5422ef6898c615f0c7a36c567255aafbb6da4f54a00c26fadf8ee27a6b235d1af98d124b1c818c61b1d46de753cb9bb4c30c1b91fdbab7a737c371b4edee2314" },
                { "en-CA", "6b3453a64e7688b27abcacfb11f6ad88c9c3c39d74f574dead0ebe8934e3b632465b79d3980a51d22979313f3434445238ec3d16ef05ded1be3380b2997de9e3" },
                { "en-GB", "df035f0b058f118c69cad273faf1b3486b08c30355bf093a7897cb4410db4336d14139b2a4612a478041e845a03d80df136a4da11a4e9ec7c9c3efe4e030fa62" },
                { "en-US", "a8d2fd394c2c7030d2827153e169876decc198b5f7fe3e715ddfe6108a1ab0c73ef52da1581ca1190594d62db4466ec8f785d4c54708b3beeeaa42a56140a362" },
                { "eo", "357305714873f5692d210326ad9c693c7a9296187c346e950fbbac83574a463db512dfa7f5f80efb4a4fca54a04dd29421ce4754033a0ff727563d98f86cad4d" },
                { "es-AR", "55c313408824017bb06dafed3c931b00f0d7f1e2dfd79e0f2c7061eb324bc6fd189d975079404c63abdde12cf5b10c3ea1e303e555fc572a4b088183f553d550" },
                { "es-CL", "c6d504c2533e8b224e6ec5164fd8ee81a755db7de6f3802c0981d8026786c1173a2ba22a9d801ff895a7ac1feecb0c0251c8a230bcb1a06dc412a9058d922511" },
                { "es-ES", "57184e1fcdd63f5b73c4b0908149a98780a35ffa9b454293316447481a36d314774e0642eb0514393511bbe4591fb6c300873a84d3f3e05acceec20f6be7b664" },
                { "es-MX", "b4c13f37fb265974e0e6166a278f7b5b8c14911c9a01172e6d79555e2545c76efac45dfb6a1c90e1e73786af4e519f304482ce91e6838854ccb6c881865e0ae8" },
                { "et", "1ea0a5b99081cc49e4d238c035d73390cc4f3f0dc3943a26a2c790f78ec827ac188944019b64eb4ec3e8b1faccd1aba4f5459f7135c2522d2794396c6f7c23c4" },
                { "eu", "e314ffd06f2f97c90183b5fe23c0819654cc22d54a1846ab97c502ad2bd209ad1f4474c5dc39707749d3982d6608f8f696dc23587a48c14afe98dd8caba9b612" },
                { "fa", "9de3abfdae8582a62ca3a51f379db4551751b13e7ec548cf216626173587052acc05b77029170af5690a3202123940f2cd03c028bb5b1064497eeaecb2e669b5" },
                { "ff", "2f82891ed612ea0794f0a47f1e184e1d1ef23ada321f4779a0e4add2d2fe8fa57a4e8cbc0939c9fe3e8ac7971c0d6d38a2f59f542c52a83c98bb1d628aee632f" },
                { "fi", "04944bec6cee4407cde62cd6b008a800bdbc489a2d21027b659908c66d3b43eb42fe3d0a8401079ffd82292972397785185e3308b8996c82e97add48546e3330" },
                { "fr", "ac5d5b7d7cb910a7395ab626fca13322379bf68bc44590b744f606f019aa1fa6b7bf9697962e87bd652499b133b6a69b40a022403952ce3659c684070b23454b" },
                { "fur", "625b90668bd9f4f9c00698e14cafc05211bd12024d707da1bcfd9376a6c8634b03695ac22cf10f99e207e8d722ad4c5bee95e515c2a536ac48c565c63cddc106" },
                { "fy-NL", "1cd3c428afa362e36aca0dba75753b48926f0aa95760240c5a028c598b07bc73c36d9672ad0c821f94b148beddc015bcf215537a95cb6f1f37bd707ef4327157" },
                { "ga-IE", "a79b7241540c9fffee6171e0c0afaa96fa95ef4457c1afcf233785115ac82e321348ed0de9980de844b0515d1a403032b1e2a7b489925149d4fb968de4a7ac1e" },
                { "gd", "a510f6c2855ce2a393d20e935bd9a42b5574db5de5d43e73b254cc8878cbc56550464fb83a0b8b6ed8875a927e4986f065ce2545c1176ab5dc88b0d72bf43786" },
                { "gl", "6150d5da614ae875c8dde27c7430837c57599e22c27682e94843a06d62c2aaf48f27dc747c25412ade6203bf46b1acb11bdfb05fc16b8a96f2ef766421ae47b0" },
                { "gn", "9c69e4d2c5124109d3a9fab3bd22068fff004975ff5d5b0cc045dbcb9c42732cb1113d303aa2f4087e0aa79e76912c896e0262cf80e2d6055d36b551e91a3712" },
                { "gu-IN", "7f71fd6c14700d1f486286ffc038efbc065dfa2b980fd959a6b1b1dc443a5bff7f3e42ba4e0357bce6c1cab0eed49edc774a8e4d763b52c4291ef143c53f534a" },
                { "he", "1e5e3855488b366b1fdde268e985638d7661f2bedf1e0169030c3cd80402c50b0ab6a2f504bbffa9a46af8f5e6df8f668f745c08ca8c71b9303771c2fac3200f" },
                { "hi-IN", "4cdbc86caaff9b4dec899bb16ddf391f7e893f833f5a7383cd719cc2c528eec31a58bb50cc1d0dbd8b1ea8811de23530f278c10af10bbebe0051fed80fd70c60" },
                { "hr", "f6d53b6bb31f2dcbeb635ae0fb86fa2fd5d6df38485418a75ff5f69067ce1be2cf5c576727372b50d94b95672a471e93af7c885a20f9eb99e01f629a46dfa50a" },
                { "hsb", "699d302582a9cd9dff1cecb52015cbf3cef3b6c3ceed002ee5cb4bf7a6a1b09a45e6292b7174b567dc069918df58939a43625a0bb7b9e341eb67573a51af99bd" },
                { "hu", "1f125b0bd7b4d7e53004eb2d213eb8b12114fa899172604a3d75d7788a932c3eb33ab8c0d87f79519f4f2691154b8bd8e686d4f08e19ed2b7fbc5940126b3157" },
                { "hy-AM", "c6c1ed8d484d71cb59dc84ba67340dd9e82ff4cac6a14c59bf6b15085e9181a36809918bf1d04be0b3e89cda850bb47bb6b086db0341b6f020464125f7790436" },
                { "ia", "af95e4f667684c263786270e10ce13528d41ecec082e70567b7f177955751113f47ceee50c8790c16d24a54575b032bab274f25c960befb00353d822ae4c5fa4" },
                { "id", "3b59ed9f6dbfa623a1436f60058f13d927cc64cf86d7997074108884ab0b7931fe317cac6d1eff7bf7abc9949f7c8ddafcf126a5af0213f5f9711105209a28a3" },
                { "is", "ff18f389eba4348bc0aa8c18ad2d4fa0d8de71a983049712df68eb3c14d0fadb56b178cdbbe956003d330e420da21a40aa589a61d90c9d8641d384ca16ea57be" },
                { "it", "2b9666ed239d18a1bed926eb1a32a261c2cf86fac085ad8212306bf22850b222be055961474088bd71f0a9c2ab9548f58ff0ccefaaca0eba5dfd0f98ad8fd4cd" },
                { "ja", "4dc2afb5a182d14be2bb9f544b3f5221717cf3e9a106921003a8c8522c657fc98752b4c3455e497e481d95a7787be24267e84472a943a59d4fcda661da202c86" },
                { "ka", "149b70709bbc53567d2bb82777ed7abf6b6be259ceb75fc6ebb95efdb780c7e3b5585ee9213e80f9ad0385444305a2c75b28129c1a5b8fd7503f23675580d657" },
                { "kab", "389bbbcbc7b5d0baccc95ec3a6bf0e1eefb5379604d27da7651effbdf849342d1bf0f9d758fd8fbbc65547ef2307c9f49d42518869955f0f793a1339175c496d" },
                { "kk", "6a658e6d48b36301c54ff9d0dcecff9a0c0a1760a6627511350d62d070f2ce5f4e07ef8e6df57812935d10eefb5044a5dc9969856a8d12e187148bbc757bd7b6" },
                { "km", "61a77bc08212933247c281e104009dc6c79abd13ddfd1a2b43c4230bb21e05f7c3a74f307d8b13ef45f4342a932b62d49c94350b5c903ac50a9cfd93a0179ff2" },
                { "kn", "355d4300617c785cc3918e0178448c555eab31579c0cf1ff2c364c5fc8ef6defa7acdb4789785dfb457391dbec5e09e04128fdabffffcd2775e48c4f05351031" },
                { "ko", "58ad25e0066c87ee6880d75a77b0325a84bd46e526051fa1804a2e5a66809af6d879134823c5ca0690b66ae28cb9a732b068affc3bc4913e328a131841e5b665" },
                { "lij", "8c1318b6d4286a62f6223a81b614720cd580c7ffb11f4ca51608841e7f76e768eed1f64553326f5afb788eb792a2b28fb2952ed66c365c5d47e0299c7c4f613e" },
                { "lt", "c4fa1c148459d2469103524ad1279de84e4731f59a07b37d81283002ce79680e8116680fec8dd52d5c87db01cf8084a6fb78f09898ee3c15420f0e9593cd155e" },
                { "lv", "69a88c729b9627f7957971e277519983e3869fe03d7285f684caebbfc40c48519091d5fbf7224bc00706d933a4a82531f4f5d4fbe81f9f3fb0db554ce1c06242" },
                { "mk", "67bbbc452b9504aeb3cb6dd9c572cb2dac7f629aa79fb20c567e1e07b9b4f59e094fb0fb22db32d7ac62e77cb15992af2e7facb2548cbf35d2898c4f467e5230" },
                { "mr", "23cbbafaa2056c24db76cafbafa9cf323e0dfd01303e99f3a12315abb57e03add1c4a6e9cc4dac60129b509a4fa457d3a8c2ba23dddf32b6bc7b49b64358d064" },
                { "ms", "0acf859a96ad371c0399f7e7b81245c68b1aabe344d5af935157ef19636d5e771a1f8cbf2b9df165fac0b53dee01634594aa7bdac35f044ff03456029877ea93" },
                { "my", "961ad14ff2063675dbf9ec6a83d89bbce3ad09273014a728653a4c7ab186ca32cb83251edca9ec34f7f3df8cfe87cb34a5c031db66180eba1fef79ffccc2e319" },
                { "nb-NO", "d8c6f244db104ee9e1618126a898078098168f789ca12ff80454fd5c29cdbc76800f83eb32ff8c3c6aab3397d2c1c4f7477342784759a5716b436bf8b872b3f9" },
                { "ne-NP", "9eabc25dcb5279386a9126b48da8c1651e9e805d3ffe36b9146e87c67b21aa9819a8ea27efcbadd25de8c6dba530999146ab9702b39103fd35ec692980a30138" },
                { "nl", "daf68eb95d2ad7173bf5d25191e1778a4a1330709abf7bb16d9f2ac904c97c0f49500597880ab1b4c14c99b08b3777c339aeb7939aacb599ed4d730067d7c572" },
                { "nn-NO", "65c4223f5fdd11f3d1372c60911aa88a16544890fb359a18ccaef735bedc47a69e2ae53b74a7079f80b6cedca153948889c4c4086454382606f87664599f59ac" },
                { "oc", "9eed929762569f308f80c40b10c715017cbac6ab8d6ceeb6a67f1dc9f26c2745d809df066e35f714ade3847eacfefdae1e051ec65820c9cd2fcdd4f492f8181b" },
                { "pa-IN", "d1330d2954e30525af6ae0f40f22a6e66740fad1f9d560217da9a94720d225ae8089ad25ca629fa8c90b4391dbdf1455408620e47c6f49bf4fe293fde93125fd" },
                { "pl", "fca91b0ffd4f189d963baf5856dbcf795caaf3b822d92e32f98310794a126df580bdb57f773940cc366a26f28acf00050a7cc0d33565df901f9dcd764fdd1610" },
                { "pt-BR", "9b14177006490a6b5ccd142c4da342f3c7434a002d0555b6736512b1fcd974a1790c51bcd7dd9bee617e02b1fd6e6893ef156d268736bb70bca521fb6ace7896" },
                { "pt-PT", "b7826074f38fc8f2febba04ebbd5b0d2bc39ae91f81d1d1dbef92e94a67280836670b09d549ed9df6c2b956dc025e0c998d52f1abf73e643516d9390a3874018" },
                { "rm", "4adb32d16a83b920b3e3a6abdabb8ae7f0562f3e9afe68414d94d17ae704b9e047f9085d329137c993b7bc93daa43cb188b720fcb20661539d29910deb612f4b" },
                { "ro", "755b0bf5d3a52bcb7f16604f9201803e67a9fdfed86f5eedf31a8d2a0a0d7d0324944aea54feefb8c4ddf8ec37d31cabe2b0930fbea4bc21b7272fdebcaf8413" },
                { "ru", "560f64080d023104434f363a7c370506390ebff4308f9d776f3d8323fc56612e6346c9cdca7d1ddf38018400ecc5efa67aeb0064e826fcd2770c8ca00f855dd9" },
                { "sat", "6a4cdbfb297de7b1bc20ea8f91cafc2b3451c160d90ac4504164808f994ff27a2871dc7c8a71e5774e51f34b7108e893bd752ec23660a4716ab81649eed3d82a" },
                { "sc", "b5a13d470c90b71d80c5bea5207bfbb47c24475f9fc6f8edb6a41aae8e29e6b19756b9d76eaeef48eadf6517c5b6fc46f6702d456911a79eb4e8899219489d76" },
                { "sco", "0e83227c306d5497b01b4232ff6dca8970222fc0588b9455e4acc9d28b482336baab89491ccbc20cca9965be5ba1d06548dda60f2f4cf6e4864722bbde9c2f5a" },
                { "si", "b3517e45f5187e41adc0c5407d2ec384280cbd50534ca2e133538be4568552f6c06784d9b1e7f696b6b1eeff97219c4ac569f31ae1c1d2a67771128dd9a2b430" },
                { "sk", "3235454370a7ff554740e5234881141523c47fd358df6dfc3f32d9b18e65d518153819a60f138172f3488ab1fc4f47772e5dd845d27103513b755b17f0774b84" },
                { "skr", "49a37ef51dcb6ae5a4515776d224815d1dfafff05c0cccc5fa9fd971e9fb617eb56d6df8acef8083ed25cd66b5a23be30290c95bbad04c2dd39bae77a30fe598" },
                { "sl", "639317bb0a81f24d0dff46f3e33374c6273b32ba996b4862eff4d18cb8a04d735dbe1228d85b51f67b8f38a503e5e4c7149439463f774264f59273e1089f9519" },
                { "son", "80a1b537b3e88d65526c95a946a10330f116d13fc4717df8dc1e4422bb501931957882f6ce15305db79d1426ce7d1552a287554c61cedb4936037416c3a5ed08" },
                { "sq", "83bad86a239227ae147e17537c75fdda00860b23a12d3a219e0cdb50275019156a5e042c2f5a87c8d9dee3a68ffae80a2389fdc7a516126d8f001f4819ee5a64" },
                { "sr", "e2625d6eba1bac649bf0ec04f1ebd4d7a739419c8f1f43303b9754b355f1fff2799008cf1a6481536321cc3a5da4381fbb2ef9bc08c93a33559a1d0b2077b8a3" },
                { "sv-SE", "f5d165d9286380d7f8e4dfdd3fbc325ff79e3fad27804f5f1aa6b4c0886f4e93f8df597f9f4543ac06adc4886e60f5e75a40e7dcef61b956e9808e0d94a0482f" },
                { "szl", "11948d301b2703be5dfb1f67b5692ba34e24ce41230aa152c30a9a9c38846467bbf15256639c1b754d21529f57001e86abb7f0333f58a41bddd4b6e01374d06d" },
                { "ta", "a47393a92a87730560d19ef27ffc829343824d747110aa6287c3578f227d9adc5055391b5a7aa836eaf45158a33f884a5f0c143fbd1eb3e15e5e6ce0d423c086" },
                { "te", "ebb3982d4efee42f8809af6fe0533794384ea500bb255bd587282da765b74ad4ea4c4ce67952257eb8abf32aa38bc4fce8cb8e1974802faf953f8ea691f6cd9a" },
                { "tg", "6b4edbab98a8080eafc519209f2bab009d29eec53d020b64e20cb4e95470469d2ef56c144a8b83652c2add294289f16a1ee2a3240d49091ca7eb34289834957c" },
                { "th", "be4b742b1fa26dd76d9df91305ce96ea2f2e03400325192faa388064784c739f7c86de98dcd10e66c72a53ee8e901ef103514c9408708ebbd7e436c20834a53f" },
                { "tl", "23ac8a86d6f19338017810b7b942a4ed8acd831f7c774548af23514d32cbb7a49034a069d7d1b0383517fbf2a2d7a9b32182a723bd58f65de89b0e7648f6b000" },
                { "tr", "b5e039ca36d83ce448fa714ed4b1ba0ac82c246fcfed5472d938008d15ec9b410dea9ae28585a8759dfb661f8da0a23683100fe14c110e507882025551e3340c" },
                { "trs", "a5325c64c3fcf553bd2576cdfefee1ba98a51a7ba507b51e20f97c26bc53710431faa28230aae75612ce357ee8af2baa055067744d89602d905377c175aa9831" },
                { "uk", "f8176809e78dfd4ed056cf828ddecc5f9b177d2df6ab6dcc4a3439f14baa81d173da045f34439be77a890b1e7670113baf76045afd3d77d955fcd3c08241b3a5" },
                { "ur", "264f13a676dad49f8dfb90383dfbbef056bb0d4d41afc2df0882246bc702b18b63821ef7748e2661183a02ce040df8b0248b2994c133ed53870238bb5e2a097d" },
                { "uz", "d270d60c9240d507ad9a15f1c258570a3d56f5161a058e48f3098c26fca4ded64df7e47732f2cdce216b5c4ef75f758888c153b21f77289030d10bcb8c20c87f" },
                { "vi", "07158eed8417430a45827c5302b09b4a7d6867e95d32837c961b17ab4429d65819c6ba6ae66bcc0479eaaabd1a5ec3cdd2e618efe40d416681e5ce7ac1c3fbd4" },
                { "xh", "fc8d8dc347cc09951dfbbe3ba0853b7328d75fa367615f91b68d5a862616e3761cd45986e66559deeeb5fd58148ce74266a17a37633cd9b560fa978c95c4a88f" },
                { "zh-CN", "1cac977b9caa4585069915d6ab3751823b1633362e387bf56e321f25e55bef5eb8e7cbff76774c5878f4093792a70f1c9e53fa6917fc7208d37a0318c30a3aa4" },
                { "zh-TW", "def2767108408b33fd33f997cee0794b3b298db4696d6abf459947188f497feeeca78e1de3cd2ab6a36e97cacb3afa8e6e799e969dd5ad513616b222535b1474" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/128.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "657e21d2b7fa0473a7f90f92c3bc3c9708aafe12eb476a4bff1f7c5b6f1ff19223e80fc9cede7f75ea1d4773f251cc2c9155b43c0ba731ba6da006c68f98c41c" },
                { "af", "1d35e5a3824102b463c8635571dc697c8720c2d30f7f130ddb36dd30230ea2dd26f3626f1e042fb3eeb6de7ca3b4ff2521a6f47f7b5ede9f6e00d32b92d189eb" },
                { "an", "03859234f80d01d81128082c264129cdb75f69fce1fff8feebd746436685477e808bb1a7ce94201f4475d200be232e04d69630a98d9f5a8e5a560450a0f1bcc6" },
                { "ar", "fb0c72887b4e48c7eafe4d514df4718fab82bf39dd1cf6beb06edfeedf495372ab1159708217e1c35b246d700acdaaeb8e7c9026d7a3ecc6ba617b6285843359" },
                { "ast", "6072cc4924f423b52e98d9e740a36efd7fcdd86155e3685fcfc5643cf5fb7b92fbd25bf3a912c5d671014b203c0e4573f527bd5b69bfc8f7eb1a2322f9c350ea" },
                { "az", "85ba9ddbd5155324a284b448df06fa0d9370619eefcebaccaf2fe0da268ed9a24d6bcb9c99ba1d152eae01a4be3c2f5d23b4e551aaed642cad8a9bd7cf5048dc" },
                { "be", "bc6187da9995cf394cd5002a5b0e8f706bffc308e1809692604642dc7218f63ff63ce3eb3fcbcb1ada4b55e6750e9aa89a22ba6b2c57585e95eef6cad15a94e3" },
                { "bg", "dbb4df0bac855d12c1987d09ebaea105ca9e5b5186d645d1e30b456883565c2aa0ad7bbe63cfda6c520ad0bd06223039b58b13dd1f17e4fc05f61a003cb2a3a5" },
                { "bn", "b8cbb8538e6a923a724a04dde4634e6c75347a04aaab3a17998075a7fc73f7f8fdfceb08bb2ef9419440d269fd99b43b803e115a0ffdc25cfe76e81a3c156c22" },
                { "br", "ffe754c2d7f11ef0b6df51815539254e5ca30f3ea3055b8684e2c30741d040b1a1aef1481b619b6e38fba3353c35919c8549a25bace96d7f7a688810d88394cb" },
                { "bs", "e9c4266bd7f19f8ad450eb7a579275398a4bc4217c67a2a49eeba0190d04d5feec54a3dd80e39b5e0135ffd9c1fdc3717c0beaa66589cec00a9ca3e9a93f4c3c" },
                { "ca", "7558650eb715ca910ad5b52da1357b7f950d65ca8685fe794dbc59545701935b47846c3651d1ecc2f6c2ed0428ee7b37f5f6aa0618a64a46e34de65b3087e2e0" },
                { "cak", "15f2dfc1076ccede752bc6fe80091a98cf15976bae3c4e8bb7f5b56953e2a29b14e0e3e041aa4d27b4a93c131d4ebce9413e416b485fb7fcbd2630267fee6ba2" },
                { "cs", "12180b576aa68b6334decb74ff05fb7883ff78681131322a9794c255edb4efa908f6668c1c2b60ee0e9e26e555c738aa184819467e2a0c5eb74abe2425bdbe15" },
                { "cy", "85dc3e3e0728ac91b4becca6df328a3e944873f573abbc1ad5f39e28f1b978d9901a75d8e51a9a1d51925cdb58e68a3c584212fa7d2d0c71c246040eb606d84d" },
                { "da", "0dca7ab2052197e354a0c3e52147f8d6d1bd4e240e6e3c2074b5aa7a9d711f5b7baf3abda29b96ff9544f200bc8de9676191c554cc25691050cbec4fa4d56dcc" },
                { "de", "4f5fd5b3608159b4127eec462239c063547afbff75c4cb53f2dab58a1ac6c582a47ba3ae08fec7fa88cb51e9bd933a5fdefe25d7afe125d6e12349b9c4e2553e" },
                { "dsb", "ee4b0b451e320ba126f959cc4c3ec631de6cb7e7bf06b4cc8ca653b9968d4b272b05022eb769bea46bb0fea6a9af719af7aa99e81b94ec77f62ae28a474cf2d8" },
                { "el", "2ba166a7ba60cd4669399b3f781f73a1d619c1d0d051c5e4b78d031fb7e0330fa230976dc6d23c67cd551a7c43226c02d78c8cd3b1c1f724084f14a096ccd15c" },
                { "en-CA", "815fee37fd59324d142dc47a4e371974295a6b2218bb2e1e1cb3795c54f0a4f273eb9fbda1d60b17e050760c627c7f21dfec75ecfca312203d30d277bcc6a17e" },
                { "en-GB", "126a2046ea24f0ccdf9c9a04a53131115793a40532c47b4ab84de01336bdc3edc8f02aef7dfbcbdd537501d2264c7ce7293de6083cf39ecf2811506abf289ace" },
                { "en-US", "60debd45503bb6b92d6dd815664b37ae382e71a7c088a414bdbab448e9f3a3293fc5866aa1dcdef66e9b0a59be891dd2780fb24c898f7ff795e4bfc00388b878" },
                { "eo", "3c68f21108a08d618f6e00067a2bf8df6e5c78da29f86f62b90a38bb0a5cc008b0b11f5f9d5da5f6ac599c2f2d6499b7a1cbaa2493688fa0d7c9aef6877592ee" },
                { "es-AR", "de3cdc9b11040564b90426b9ef3bb090ba64bb4232d881a397c9b9d1d8db188125dac62797c3449e9a6fe54d7824cf1021edb34346e26ae1e98e604556f74fae" },
                { "es-CL", "1d728e747074d1de6f1db39002b919d7a5265c3b4e08330022f328f7dee5930923e332771f881541b5e678c236a2d0c199602eefd0edcab563b8240d5d047321" },
                { "es-ES", "ba2fbd2b61fa3acaea8ba29d6a10af5b63766ddd2159ef1903bdda1878a5613464682bed6cb9fbba3ac139786f8aece6656753c6372ae9ccd96451af408ae9fd" },
                { "es-MX", "a9465043c977aaec89de36e5df75bd1732f1533302ca4c351c4d59aa130122065ebbad3a7e52a5c814bb1d0296e843e90abed1ac46b73619b22d48a2d6067eb1" },
                { "et", "398c2c1bc246afba3f0c580ac0f816a0f56b4a1151eb8f3a198fdda334f28f2d9237aea3952dcd6d39c268c1562383d5eb1024b48526c226717bade8d4579bdd" },
                { "eu", "a61c02fc977377246c02b24ba29c933bd6fdb9df782fac78a090fc1e4e805c26e6c2da95a849e4cc9770e3f026169b171d9029ae6478fcfff2f0e8a0ee707678" },
                { "fa", "7cab6697874e0ffc5d8583a9024fa1ebb71838bd04db3ef2e1dbbea1ea5055fe5ecaf2b59296900d219cd51f4d24a158182d1e324ca6353f5541555799d14187" },
                { "ff", "08479ba486a243a2ae7e5e109d49264f63215fc7086db4f12f34786e2e5faa1b5f670b8d633625730c240364b62ecf4b671386c8f56f45ec56849f6143780d86" },
                { "fi", "fec895ce6dfbebf804685b947ddc1052bc102113559a64c324e267ba285058bb85c0a03625c93a02a7fea14053c3da63a262a83f3e12d7a8ec7b0faf54485a92" },
                { "fr", "e508fa37b46d56580a759189374be59b71af9496b253d8902ae8374ad61b152badaa62baa1b1d372c5d58835e1ee6dbf3226a05641c2b78b2a15ac6c2917c445" },
                { "fur", "378607a0b0fc9cf70aba175aaa55972532a629b352372fc171cd45505e63cfbcf71c9c9d3b24a7a1c805d84d87e69f1bacf439903a88dcedf53d5e6c447d1156" },
                { "fy-NL", "3d788dbe8527e331bc292dec111cecb113cd24d501380dd366065a46792b8741fd6d6b02fa00bb75b3594a26deaceed6b362eee1690773a6058d6dff4bc8b8d4" },
                { "ga-IE", "bfc2fb988f9956b2d210037c7c326ae49ef3c17c187ab592128d46f5c8733a7ca0ef57b4bf929b8e6fbaccafeb0ecb01365c21a2c4a1f767f3f95df4af2198ff" },
                { "gd", "1edda6cec9bc7894bd21ecec0adfebba266e72883baff7644e45fcd652126085d4394a7f9537e8a24667eb167ff94864787c98225b7c0564499084bd379756d4" },
                { "gl", "2ee440d231f101e33db614924fbc7202689c4ac51002b7b043c564d6ea0393626bbd84b06e20020be7ed5b727f202ab33febdb8bd28ee8da9a4a9160c4c8581a" },
                { "gn", "c18d02a32e6ee01131491659247aa8daa306bf60fc8d8356a47a92b43c3d222ef47b20dddebe97be84a8e87c9d3cbf2b38f7c92e7d071f06fe841394c6c54555" },
                { "gu-IN", "cbd7af507546a2d5425a549953704c93f61a98ab554678b045b44d6c07860eba6d85dd6fa88fbfb4e9a7d5ba59c6052e07ee4ed60a37df4f6dc76b8610ec3885" },
                { "he", "1e616eaee549befe9534f9d7c0aa8f3daa35942a126cb9af62f74d235c9b9f037d48c4c3d239728a5fb6f9d4eed25d44f2f83d32c89c7870067f9881c6eae2ed" },
                { "hi-IN", "2b1fbb67a5cac3585d0e30570e38fd77f9fc87333abbe519528ed97d47e1a4bdf4ccf3eed8cab4a4d30ab54479be61c94d94c1596db0f03e7c2822afbe18b323" },
                { "hr", "a15965521a7f152937766eebb655c041d0c95ee51d726fcd909222042dc06235529b501b01766da39b19bb8a68db54bd1fb0bc4f60e17995ad2d7e27959cc81a" },
                { "hsb", "3429289a79ac1ca4a7c23c8b353d11700e363f0b1aef84aef236aa55155d070da127bd5a2c972b996ec55314f97d2ec4c3c9b278bdf47483615f4f229db3e920" },
                { "hu", "1ec243d0fc51ba336c8f3178d4765832fa1f599f32bc32db42c80af71a8bb837eb488d8c7feb5506e875d9336d35ecb852233f7e357b69365205946a2f59d1c1" },
                { "hy-AM", "80ca75a6485f19afe226a660ec560e731082948773a9ec51c625b70be9f715203e577da20953e89f89ef022d10102528940e2df061ec4d7869673f1fc9112933" },
                { "ia", "b610d587412007dbfe14fea1d1b3a8f91cb73762e3bac7d77ffc8ff2f6c279dc6f657e01b94a18575bfc2d520b2b8306a126638d03182253936803b2b24b985c" },
                { "id", "da5f53c53fcef25c5a2bfe7794778a60ee5c449a58de00d8f923dd8ff55a0bb95f0940f7fe2218391790dd250f10a818082ecd02a21123b971f06144bc63d1ad" },
                { "is", "98ef2af477f52aa18c04bd242149d5e7f9d170cc758b3f30d479e746b70e84b898b901a7dccc250f563646aae94e411d032908ca1b93aa0f1ba3d5bc9b631a0d" },
                { "it", "aab39e65cdf2544accad8a0cd2317007086d32d787da571a8291c97f51ac688cd5bdfb024ad6431343b5c9c8a1abd152b315605993742d59d4de01b505dbf9f9" },
                { "ja", "ee5e2c8f159997b7fdf65532eea9a6769da86abbe666424f606d25dfea0729891e1e735cfb88b32506a58c705b0b09678cc041891a98849a21f42345e9877659" },
                { "ka", "95451c753b55459b811886624b46411d03de88064a9b04c59573c2c756fd69ec617aa9e74100117efd18e6fb29b014f72654ed7382bf59e4a8146411f9c6a10f" },
                { "kab", "ac7d94066dbed74d19aa39f79a2af686185e835d14fa0f69b9933f634fb8453980769164022c9bc28a0ec3543baf92efb1090eb9d4da7db210a8d7e65b880495" },
                { "kk", "a16d476aec402e7247cb5b3bf0cc478cf62955a1f0cf77b056771a394cd444b870dd10686483a2276b8dbada31e4447659f2923af17d284dd6c9847285e6ed88" },
                { "km", "51c4e6b9e174ade74be489fa425bdfa04828f83fbf57d1e54db91248d27bc48bdb50face382ca9e4be66d83751fcf28a5097d250d2ad78bc0eeeb0cb8a4f165b" },
                { "kn", "619eed672557ca5411b770b05087f014ea6fba26937d7f627c6f2f1f054436a2ccacc31584b50248832b61a7f70642ff36ff1022d799b9bdc9fe2bf193735d1b" },
                { "ko", "4c826fa99bf7c47d5f5fa26b2b495a31a70df4b02a9f19a48c47903fad1a5ea3833be66f4a14fcff8a1bac8785cfeea3edc446e4b6c80244d47946b077748783" },
                { "lij", "54dd3b4486a9c73e554afb65d32a36b101697785304ddfd673afaba7522f3e2812e5702f5bdf0591bb2ca6c0c33d246dd50a8dd912f6cb8aa88ecc29cf729fd1" },
                { "lt", "1d13907f851441a881a3dd3cbd3d7d50e23ae9e8b56b8c443acb6bc22fd531ee636fa7d6475dfe8d5d101e77a6766d007645a05056cd1eca3e1866cb43b1b84c" },
                { "lv", "34a075e1083c66501831ffdb019d359fdf8740a55e02d8e852daf18f6f7c6fcb5f81d6813c466b6daf3646d6f41cc2b5446b2c321b76e095ee0d5fa3e68c4ab6" },
                { "mk", "9c2527e7f66e10c18668cfb421cfe3fc14753151084fd9c5442778080f5b60f5765416c25fd93616995fa2dae10d0aa263bacd880b05990ce49e7f17da5db14f" },
                { "mr", "fc72c16c23ef4aaf38f59ffec96908c065c99188809ea1dc654bf7362b9501a4497aa3bf0f5b147940df113532ef462b7cd298db332047010326f4cb6fde058c" },
                { "ms", "e76b1bb752a41f92daa818161bdfc527c841aba856389408ac0d3e7e15db6e738418c126898364d09b41b8e4c831ab5b98f218233cb274a201df2d352bc7f5ca" },
                { "my", "30832c47a9c5bee35e4965111698fc25ae311658f3ab4669a9628ebb430200a06e3d7098c6ce448516d4e6c0f283d79a26dce52b74002dccb6e7aeeb96b0d2d3" },
                { "nb-NO", "f695639ad9e7e0380a142403fda6297f26bd4a86e3e064874c9e391ed27ef048d454fd1f4c48a0bdb8ca598fb1c1c564e73a2e985c08b1eabc9b37c3c73ddedb" },
                { "ne-NP", "30c4fdc52d2b0ec2b9dfd40647c7404b65bc91fd704b0f27cf4ea76a522b7dd08159da636e203af99d45807051d1648bf73e591b0dc28cd003e3fb1ffed8ad2d" },
                { "nl", "64808ebe5f29df567a5e4e76299df40bba3e41aadcb96457527bbfe00ddbe6bd88db03ee4d872897a96d06a5c3578eb89667ad3780b8a2aae33565143a2804fb" },
                { "nn-NO", "2d9cdaa5f93ef83047846e8f9c9130803c4b92d951bffe5396942526ec8b7621dac33b133ffbec5f63ad368bbb3d1c52593f26d15e5ea60a5c7109ca40be2d32" },
                { "oc", "b2a9f563cb68000538b29f66cb72ae886b7ad62e681ba0bbcd30920c3493374e6406ad7663bba8725fec034de7b432eb09c6694f21865abdc79364d78afb0bf0" },
                { "pa-IN", "51b45f0eaf5d72a66fde3b59d8c53d9b4bed79be6efd1e2063b647a5dd0619b43e982504ae622014d9cc63a49bf7e32856f0f9e57ad78adbfe3c97495a8fb1fc" },
                { "pl", "5660d2dd693331760706bb70a55c7f43fe77836436c496cedb5460c4cca5a9678110a0627b59363bbc9bfc086109a0bc62e912a7ac14d6205fc0e66f30e23459" },
                { "pt-BR", "47447b03c23e0f7d5434e3d71d1bf7af2dd18f2006f42f29bad8959d578c0dd1bd0539a010249d169b038cb19b7473a896499b9dae9e2848d11e4fbd57a6929c" },
                { "pt-PT", "c541d5d4d144c49bb0a2a7d71ef11280872c3f32706ac1d0d755f1dc886f378b9c8b55bbc8655bb12da931e2213102312d30a227b8ab3a7ac6010bad1cdb346c" },
                { "rm", "d66a49afd93e22c9d6362dd3bd9af2addc895e0018febe347e013ce24035f771b6eafa34de4afb1853b3ed9e7a41d5a1fbf1832de5de18981521365489388202" },
                { "ro", "e34b58a6edfddc5cf7bc03ad21c9cb4c5aaa6b572860f0ad5027866277116058e2b456ab8f74c06036e915684e90485e88a0f451acab2de67e38a47b97db6cbb" },
                { "ru", "a8a1bde662c9b7e55e214212ec6fb71b7fcdfd59633d06e76923f9a280e6b9e5284157ddd41687a20b9bdf9f8e4d9906314996fb55f8ed3aef4eada9b7c6256a" },
                { "sat", "1f1946ad2ccf7121c05e241497e47f2f1032d289046084625d75623d45207731cbeb6db53e3a6278d62843183c7f0c00e506b3b9be0102b0a30edf04d5ff5dc5" },
                { "sc", "abc0f2f094d40040fbf570c40524297d83ed03b52bebba91b54d85959252439a9bbbfabea53f42b45b40de9947e31498a4b2a9af8d633749c016a29b8a6bc403" },
                { "sco", "d1866c9428a93ef2d081144c9ae1d0650356956d310467cb8eef48de57c4236b438898cb5c3358b86b799648b6454c7e51ac70180019e87152fab61b34075572" },
                { "si", "b82b154802b41cf5b0c6562ebeca5922662c33611611bee07c3b68314cfd3a9df5b7048c58099d1b1d02716b6bf39bf890d993c472cb6b578436a0a1b2dbb4ec" },
                { "sk", "65347a4ebdc844e58e74e8bd060af85cd1107dcdeb6a241b26e63a6a229a8f78da1372df6bc8fd4448af8503d23f9867b2af725f6d5b850807c8a01e2974406c" },
                { "skr", "104cc1486f03fa52c48aa03c7aa72d43d19f7adafa081da12489b6343988856bf5734c8445d57908807f459a9c92e7674029d52dc74a2d95c39a8cab597a75d9" },
                { "sl", "e5e588d2bf799f8f8a9ed16404a4fdb9bf77ed9ca05de9c17900045ea755a81095121a65d0b8f1bed52ba0221834c2f830b268e95fac7a6dfc1d49288ca22720" },
                { "son", "92ff2e12dc3ff0b318b0e4bc9ab02df88926b338b1ad57d4aa1661227eef50b5ee871128276d8c5da1ab4a572d4366bec31478115b8ff35b56ed32320b801a8e" },
                { "sq", "1e088b6598b198502bc5d591b207997f435ff2937d8106aa3aa86e71ca838da234ec7cfb57e8f5706b37f8a30829dc1a24ffb06a05d1a68c3cb0face63a95505" },
                { "sr", "8469df951f4ff60673b6c23f32fadc7b40238e9f22453d8ebd377a657dc50b8f355ddff81fd31c9377f7f2419b0f6d3632afa992d68174d534672cd7ad23ab18" },
                { "sv-SE", "5f3fbe7d4f5791c8f37c278d9bdff42a01e5832b63221f4e21efa22a99083b568a5f58284185da601b4baec6d12910ecb945a6955f4fb21714eae2969f7e6e2f" },
                { "szl", "f2b2bfcdf3f2e801ef894a6046743aa98c12074af61dc09e8eccb962308e69561c39f83b25890856d98fbe36e3fefd68a443e9cd215d6527a4ff59740624eeca" },
                { "ta", "ef2d4a3e1c91903c3245b6695eb256caa8d22da22ff5becb812c654b4b40474fe91d658449400428d8f9c7ad68edf425a3e8ff107c497f88cbaa9a977e01690a" },
                { "te", "168d18bb8d6639cbde3c47f30465fd05b8b20527809dca78a650e9e1bbb95759e658aa2e9387c25f7d0ea71b232a8059b92a981e95adbf9ffa9fd2e87062bf43" },
                { "tg", "ff435734079b0d9e8580f697d376d6c1986d7b321ed6b2f12b443a7f9819539a601e136e9f1400882ceb0ffa445dc8552defe530362ac086817185e317365618" },
                { "th", "8881ff1d5bf6e5b9f7489b4caccab97da10586d1b20adcb54107e2d633df368517ac035b01835515ebf3c6131c7d3eae764837e3efca84e80a5307716b73edca" },
                { "tl", "5694a4dcc5f408075486e7af8c7ff12022dd249e712b25f6f2d2fbf1427c42064a82eacdea4e835fbc335b45dfa9e28f4c14893d4c17acf82bcd3909271d060a" },
                { "tr", "d77b6ed70cf8413a50b286d2257a1694f5aa4e8764f578669f6f33647616e335770979970dad23520465616bd4b357c0e0c73d51db39dadd3aa8ac5af8c738d5" },
                { "trs", "6ef41279fba4c1317fa39519d1e039ec4dbe12126b2ad5d2d44f12499e104329ab50fe357f10eeab56bbf76925e3a4a1a0438d21f32c602950dcbacc68bf1dc5" },
                { "uk", "a106ec6cf08bf4aed5bef4d8c3e4d62a3ddbcab9e3debcd2ad5312eb9fd346968a1ccd31fe0a37be1d3d93733a1f355454057bfe8f9fa656fe2aa8f8a0f35238" },
                { "ur", "a7f19661c483b8d6c065a0250c97f0b3e7883bdb65b17f206349b1d8708e457251b53b078754bcf31e84361a16c1b749affb12ff3021779e795bef859b9a5749" },
                { "uz", "8b645ba50e2f57b1be6d724034bc9f4811aa7d29c91320c7df21143d63c7fa209ff649d0fda2792e55906f97980e9c516b5c61d9f2be31477523dc8d17a1afa5" },
                { "vi", "f387e391d251f57a6398d86a9a27a81f6c89532b7cfbf006ef9cda298f73854dfc37860ffff0330b6387e8412cec7256067e7941a73ab1444c0c87b680a520dd" },
                { "xh", "8ee98506d77cf81c77bf8ac99dd9bd20c199256b4ff2b2a3e9cc9f2168a0b3d0663ae503ef529f633f9984cfdc30daa665e8fd3c688978b7b6d1e2bd50342f7a" },
                { "zh-CN", "cbd72fcac4cf6e2d7e6e19ee593e104f891e181a536d2b5f294bfab9e8950c2a39bdbf3e95ae46f536e3a1fc04f5561d7cc2e6c3089632dc403f9936d7b8a7ad" },
                { "zh-TW", "5a482de16288ea92cb794dbda8bd312e70d7171097a4f7290b6a89d08a32d044a45932b6b2e0051bc71b67e2f3222f72e72779c6a5759c12c3618c81b2e7520c" }
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
