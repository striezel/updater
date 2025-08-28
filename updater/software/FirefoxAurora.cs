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
        private const string currentVersion = "143.0b5";


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
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "58ad6995515dac17273339e6881a27d7ff54812507c1ae5c40592f4ee7d6de13c2be50e4b335f6029f7d172ddbf6d11cbe7da75f4dd8eccce22eddf3120e4abe" },
                { "af", "6469f284c2e1ab7756a91e2b93bd948fb7d96ec8b47bf7d12f8c8015e7cf6304bd42ce06c859bc400151c9c134734294b9ed1e90082ba97d82a7fbbbadc8cc7d" },
                { "an", "3132ec8ed2159eeb6d990eaf9ec0a1f6cdd544d3c3c9e21e0938a5ca4ad868e0939e2f24bc252311db68da74b4acae0de758648df30f84f42b010b50291fc13e" },
                { "ar", "087c18a9094ad7ee639102524a807e74bde38eb48cbccff3c7687af3d061e2fdb89b245ec7806520696ab919bd83886db6deb1d301616e8d921b5e59ce518c25" },
                { "ast", "e9b98acb612525bb1da31f895547be26657b0355dccd1fbd1ae17364156e14eb2fc81db8f71130adca2a158532c9f4dc29cf13121f783435894c7423a938a4e0" },
                { "az", "834a33288616d4d256f3b65cdedf94cfbb6495224cbc22d1431934708f22ca7c5cfbab4005b8e79aef3cd10de8e9eff4a7ce25769a2c2b90d4c8c8c333883c7f" },
                { "be", "02a0c22e370b3cdd0ae113ce79c82baf711e2ea7d6f72eba58704eef1b0f11dc301ad6dc7ca6879a6c52aa5b8b496e4ba27626a05ebafbc6c1e9659a486c10ba" },
                { "bg", "daa363d5994a16f741ea405b28371dc3d830fb6c91a57d864a611c50ee35af8a704aa248a162c52ee12834e2859e437246d896f20612e628bc62eb454cbe9746" },
                { "bn", "8dd720ccb4832d5908a65da3f503760920edee45fe98e3909eb99e08a352216ac61f42a76f9b827ae7cc95ed39148494d8dc4ff897f8cf75b2322a42b32c3b26" },
                { "br", "7a2e2dabac6f3f5d09ecff050dab84144fd629a37279545d04d4f095d343cb5f4e1ba7708d14f9ac9fbb4e89b9a4a9b612ac04f80aee68da69c03aa15ab8c0b8" },
                { "bs", "0df6255c3dea14fd553d8b139e448d30161bf156d1c07344c14955ac29e9b0144b7770e32fc6bc0a663eb922a8ca661a553821146a26eeedd70a0aae76460650" },
                { "ca", "c89dc89e95fa90da492eb2d51512bceb651b5645235ab3761a58c8c382359931deabe9f56947450cc2f8036ce94ff9d81a54fe4a353827b2b27358ec97c2304a" },
                { "cak", "33a1952c7b130c7bd8a2ca1d9d116406bd708dd9d32edd960b4f1a466038fcd9ede0b398f26eafe31622584e3a226a8133838dde6eee989af3c15145eb4a52ed" },
                { "cs", "750c5d868792319db863d3ff975d10e5f363b1b92621918e06995fa7309fa0b03c74c9ec1d98f5ae1e893e2467b4b73c9a0ad7c0e94cb5e07297902a9ac59a3e" },
                { "cy", "caa6a71eb877baa1d4b028b9d2fa1ac437923d720476fcd962725f1104c45bafddc90cbea4dd0067ee794ba86f97ea5ed7a5839e94854fbb1a8ad339be648ea6" },
                { "da", "33d281c967e35af56c981a8e7114dde455844631e5a529d0cb35ab38a1cb1b6a28cd801ad283c2c8696ecbd765a2d37989ccbaa2ff2e29cf831438a6b07b6d3d" },
                { "de", "3b75507db149ea482476bec7f0fb4b1b522d1835da264665ef91e6045f8a6adfaeb553317d22141e756b804c2227665764426d0ddd8a2ae1ceee88c5e9fb902f" },
                { "dsb", "419366154dbb6b3a568c8e6c5b70aa5e5ab4f8075f184736030f798cc474af0587f2b4a24a42dbf24dc3d6a2a8c8d784ea619210f61baabfafbdd16dc8ccf6ad" },
                { "el", "2f2c8d0ecfb634d52750e72c821fa04df79ea83775b75dc58b0f1e4f30b411d35caebd556f1c38a8166d6342fa6f9ee57d629a4f55b8c9b008678f0971b46dd3" },
                { "en-CA", "c675e532713dbbe21cb77d5717e4f88bd10cea70da1ca25312508134470124d34445c1bdf678833b6f79143fd5236b66abe8154533e8d342a42d939e9715a7ec" },
                { "en-GB", "44da64b9d86f55bb6603321c22561d898e71ebf01c1fa35cbf155dbe76616c24d7ddc3c8f6fcf34f47bc2f35b70412e75efece5f855753fccbc7ff2cb5ae5495" },
                { "en-US", "cb86ee05a3de33ac7206bebdc8c883123be8ce4e579e02733d0c1054b523ae375be15dd52a8921a515661c2bb3a6bf647a4caf29fe1fecdbbf41055dfe77d891" },
                { "eo", "6c81874eb2fb3141615182815c053d9b40d759764ae929dee3365f7c039709e23ddd44f76528a4748df4131e35701bc411be3cb4cc9c73ad8716f661e543a913" },
                { "es-AR", "bd2e3aab5f1edc0c9a12509a55582fccdb13d8a7da6cb7e3460532fc996c18409ff759150683ef27dc6be5b5b9023febd36fd9cef011e0a0e5f03bbcacaac798" },
                { "es-CL", "1dbf088c23f1155c3b9d77936135b8fb043fb4dff0a48ced83b3da6d616bb4dfdf079775a2d892db4c7fe09271957fa9b69ee18ef9360cc0dac42c37828b4b6c" },
                { "es-ES", "827b3ad6cad880d5d644b63670cf4ec04cae0cf4eb94a433a9b744191cbef066e251cec3a9de22c999dc30952db33c61701cd232a4d0330561e4932a19943762" },
                { "es-MX", "edd6e73d889b12a684542dda8b6f810650f6656f15cf15842a430ee17ffe86faea23652efcab9026c8c19d2b3d031db9506e02200cc9dc2ea2f84b25b4e5f1fb" },
                { "et", "b3e333f94b82cc5baf2ae529d346fc90dab259cc94f7b699ac2e4324094412e63142f2a4694627ef069d8992c8a0ff4b85dba814e34b2af6ea6e1a03672ff98a" },
                { "eu", "5eff8f661bad0c7f9026f24cb2a066d5826e2b04288db24868fca4eac0c71f93fb3b047ec0c528798d41042303d5fe80b3c4a95ee404da37ad0ccf8bd7c7658f" },
                { "fa", "6c4e989edb2dd6f7903e70f4dc604edc93d6acd59e3e129d691cc03dfd4933ec180f5a52749ac137a1722bc5a4e8c978885f3358bc6965c1703e62befb902a2d" },
                { "ff", "ff7f4cea4f04a9b8fcd049e4b86dbfd81d75848bfd2ce7069bb897216f59f0f40db2813ba751688c49fbf379d41e80d3b38992935958d13245feba75eb8dea0b" },
                { "fi", "d2efbc889ed8de4a261380cdcd45226a96c81161d28003c386005a5657b638ac3a32c02f56a20934f60bae17f542859c7b9b251358c379c6257d171922ac9556" },
                { "fr", "bac8d7bafb324b53e9e61464752c102a8b8e159f0d07eb9e1b819465c2d56272bac0e7728bb122261bd5e320ed86733af6b7b79961555056c856ddc8271e5acc" },
                { "fur", "46a703294be6ee361ad4a0e855a56789166c9875e183dd6b4fdbc6383035c2f7f9ac90a1930dd40aff5a218e809f5ed7cb38fc980e8b816737d2a6b1b7288c9a" },
                { "fy-NL", "e102e98fba272d076dd4ee3aabe786d72971630e7fe4ef40de12d63eb30c2499efc9e662059a6816e85c330ed40b7eb2e2a003a7a4c2826f56624ffbb018623d" },
                { "ga-IE", "c4da86e763f295dff0ff6da84e9621082d3e8264df8cefc73ed3b9e56ef8be8db5d956d9999a369e978b16033ddc2c0d1ba60751c59c0098bd58e18dcf111bd1" },
                { "gd", "73fea8e2c45d58fa0fa435458845eb03759d0bfd9722203c55db5ccd020852d850196b0b7f8f074cb2d74b67ffe67a747efc1207299824c1394306953c159c49" },
                { "gl", "b0c8cbef78069b0ed66dd475dafba985cdc4227646217cbc304ee248da9593094a73b12d5250e7095ed020472c7d122199c29f48f0f032f1ca49cfa4f8bd4265" },
                { "gn", "d31104c88a0537859a6ff01d517d04400c1be0b142a1df4b41099e47f61e86b4b69aa5ededcc03758ec710494a9a6b70484f07ee0734d74f021f11de77d9263b" },
                { "gu-IN", "0d4f2c6fc50109e6744889333dbdba678bbdf6446543b41fee1661cf541d6c9018c6e9718d1bfaea45edbaa7fc43500a835ababc6361046be93b39c44f791368" },
                { "he", "3a450cd1ed891e3d03ff961b79845a51a8b77878f8d0f194491ff4073405b355376bcfef0bdb240654d8ffcef8f27eb6ccdf70cb6d620ac2236f9392b8e99848" },
                { "hi-IN", "b8e7c0c32a5de75d82d8ee980e6c7f13593c91aff4870df5b7644299a7260db0db08cc34d6a0cf4ef13ee5717afa0dd3b3192e84e4eeb548c6ff7391b5bfadd7" },
                { "hr", "35790796a991978dcfd1ece2e66a090e5744b5be9d7fb143c3f450ac74c8e306f14ff69a7d9d25040f27a4a8b9f57cd65ac0cd84b50416d7f4a4d02ccd9e9f7e" },
                { "hsb", "aab228c3bc764502042581a83987c31a82820715ca50bd2549acb8352e1d980717aff49378d129b02206ebf765bc25b6c661579e4b94d76a70363fc13bdd9871" },
                { "hu", "687bd42bc4d9f33e67b2ae8a0de35fb2e96293de646ae548d7965fc0dc6b4269fb278d8b4188e38f3cefef7f2ec1e45a8796cc4cf73a51fc6bd2b2777148c38b" },
                { "hy-AM", "b3ec30d8241b4dd020dda71051c55e2dc657b32a4f7cab76e241b5f7bf87131980b4e30d8c5e0dff55f5eaf8e486ba0c0f5a18b9a1ebfd8ae421c1e7205a07bc" },
                { "ia", "39429d524c1b195b555474a881ec12c64afdce3b80939a1658bc25c5da19151b9ac7a3f30b4de56be70cdb1254ac6c5b46e20fc0d4b6de4ecbc762b3cb816ad3" },
                { "id", "494adf15f555f68e063a63d553941b6411f5a3bdba0f5d7e22639e820ff1d9a78f442d39abb9fbf42e223b05201f449a7c94d82280d8587500a0717c95666b43" },
                { "is", "3ec73b58324b7de5fc4ae71d86d2b42a29193b3530d6ead325ac5c9a34814698d46076824a7de00cf46285586dea2380ffca189e6ea56f4f6436e0e88a77b071" },
                { "it", "562949c54c5170165b2fc60c1be934839fc4e5d3dcb99d0275202627979a585f0eee840744b9b514d35966cf1dd0e27d9d033da8ab35c223ee3af714008038e7" },
                { "ja", "3e38c586807cc6282c06b3d4ccd04119a6bed44ac0e3d44ae1266c81520ab65919e61839518a5390eb41b9de80c1b2b399ffb4ad51032b6efc7fe97a91619f97" },
                { "ka", "99001ad2e97f2dd77cf6549b3bf8e2bbe0d89b09ac6ee37166eaf5101401396a42b02893316d4f65dd4a3c1201affbb5cb6eb4a4ab5be87a685c3878dce12867" },
                { "kab", "ac7b939dd3d4039d80834adcb55c134cf1fd070a991d635b2652728e024ffec490a3a602953d6eccf18f6998a899bdfed6b41740e8c078e44ad949c677e136b9" },
                { "kk", "bb4f694d85800f9fd1f3b09685c6162b10da83e8a1e16cca205fe7073b5e7fc5ef15ce4f3cf16f5fd1b35a1b4e0bd1c4ad6dbe59cfa752c72edaf0c486dcc826" },
                { "km", "4d03d28fb0dd487f63d47d713fd60d6f23db0fbba086f0fa432d1c86c8b71c95ba85c8dc04d871163dab7de12f24ee0d3bfb8512d8eda752427c14f155e68240" },
                { "kn", "ae2b3c6b222ccda7d3c58a1d9bcfb6c27fa3fabeae180e8397077612b1a0f379893cadd7af83056d550a5ea80de643cd3dc398e4996f841f6573cd1a654acfa2" },
                { "ko", "8886235dc35836707204944772cb9ace1581e70f2b62b9946ad5b7f500f603a2bafe5bece529fc03037dd036ae81f6817474b62428b48834c1535dd13fdb5572" },
                { "lij", "e50bf1c51926b80e99eb0e32574eec3aca3da3aad28cf1758ad551eb4655e07b197a5d3ff625afc8ef0b774a7c6c085c95d93c6654a733b85596534a5b2beeaa" },
                { "lt", "b91444e4fc9fbb6a3c5c8b1255c407c960a5d0955f5d795f24dc44b962b25d940080036b85f7b3b0f8e3d7de743d2bfab2a1a169d3ead783060a26f82d0e400d" },
                { "lv", "e584487930f71ab00fc2714ca020937e68cdc2d45c7946547af0767d759970b44847276cc0b7d3c618007632b72eff331f6cbe0b926efa5677022b34dc5309ed" },
                { "mk", "4f48a8912df74b6f21ee627ea1dbda10584311200d4a683d9907b4c5697097eaa2d1ac6ea0d607b45e780568c0c22d0d2c5100ec6b4de12bdd18b353445cbf08" },
                { "mr", "cea406625e5910d4633027a31148c8a89fee781d3ff2c3ad8ac4cecb20607b09898784c3ee0650cc2555889d9bd4240da9fd3162c2fb5060ddb2b053cb8851c9" },
                { "ms", "c873f1f7ce54c7ea3d187ae22a63182204e2f954f7c8c1525c560e47365ca3e442f231544085c943fe74da1a69827f2d9f0da1e4a25af96f82889c4913b44b06" },
                { "my", "6bd6f52619241ecf670c99e1b2b63cdece44cf3da61b0fb3ef584f04f7e6914fa2766194c0105f42e18e3154b9862adf0ce8c5458f05af2bbd87a9b9a5719125" },
                { "nb-NO", "480afc64a3834af792db1c29a02ed4b2f8cb1f6aa07bdc88c41ee66811e33f18d5b085974922d8369284167af8532ec27d151a437249d16b91c30247c6402b01" },
                { "ne-NP", "cea29de97ea8e2422f549e822f57340e1c7d3b2a9ca59fc2b02b09f2b9b5ef92e6927e4b868b3d593027c7f299095cabd3972f8e3474f73969f8f150e61f5378" },
                { "nl", "79374984d265a352ffc2bd718d31c184922ebff27bf5c0a3419b8c8445bd37de562b00e13f1355a2e715106c3c3d5879d59c4697125f99e0931eaf2bfd2f12da" },
                { "nn-NO", "07d9582477bcd875596be6bc878f1a3af80c20ffcab08c2daab9d0b7267bc2fc86fd8d8268bb020c2c87f7d20699bdc49a7f1a24d333c2b526036fa5ec2b2a76" },
                { "oc", "310f92b2498b00ced38d691135b8c13697ae08acb9c52b7eece52094f920e59ec7215420b7e5168f9744a798b9ddaebbd12c1d3439c22c640d33b6a1e460ebff" },
                { "pa-IN", "e7b7a1278f9ed8df5c53beb4e86641b77a3bd3857a37bbbb66b3cd9be53b0fc9e5a6178b29dedfb06107d3b2c89b12fb48cb816c96055e502dd97db2810b8ed7" },
                { "pl", "5cc6d09f4c5421b6ab921ace0e0edef53248340e2be536042ab8976857386a91231d4058062eb6f803e552a472933c28b469d8ad0d7ad0d244ece8664970ff2b" },
                { "pt-BR", "d0b0ba96b9e74a2db17229a2a66b56aa3028672ffa41dddd5bac5088b46f88c04e372bfef5babd757caf02dca57e7d38446f084d307b9cfcc646f66b44503d59" },
                { "pt-PT", "f634ec5c177b5ea50377c391b4f4843361a4ef1c77924709760c105c031ffb19aef0c02a1e22aeaf4307544ecf795de6356889eeb57efc20b8a37748d6895f36" },
                { "rm", "b1dfaf9c8164bd5bf4fc21b324f7ceba9a9a502d5a48c2e00b130c7ead06cea89382f74e618b47b0937e40da88f2a0d5aa487d655952ec6cbd35681c47a182f8" },
                { "ro", "a95771eb59a9c00b662a88ed978835456516a9f997fb922313d50362eb0731b17bc51a2d1762307a1b9c4c410f01f34cd93a1dc42e850aa9094c56d8e83d1325" },
                { "ru", "064be1452f8f7fd103879e4acaebe278b6a8a5f3656ff221c1cbf5cb3018c01c890df93a197abacc2fd46d25c94f7f4039ac152e8792598b127cda1b5c8944a4" },
                { "sat", "9af78ba1202d727a088a81c0405876a553ba6d1bbdd7e6272c926ead0cf302230b0496ccd5ceea84cfe911da630f5dac33d1be1b527ec24763864707109b2652" },
                { "sc", "6e57c1518bb1af9ea07c4b92f345f9199e94c8785b514106e12e791d173e0b7fbde46a8adeccc74c9ee735d7217dfb19e54f41290bdcc422329bd6f351ebbc34" },
                { "sco", "5dda205a54d632b8f89c720d80594270fc7adf9842b5354af6deac7e4c1a2b0fbb61d90cd75ff79adb933d4104e8cac40ce9853af4e543963c2be0a63d415caa" },
                { "si", "9787eb1b0a01517e617fdd57001eedb0519f5456c140ae680a7747be8fea5166952d654a3c2325fb1fee2c74ec276249b3b96aec5da2dc5aceca6d6523fd32ff" },
                { "sk", "ae2b09503b39665299221fb5d2ea2fe4c516f2c620b04a3956711eab16a9ac7ca1102ab6707d7185f0dfd8bbeef6b4ac45a3f1bde1eb740431da54184afaab1a" },
                { "skr", "45b8bef3d8782a79f6afc3077a5ac30ab90cc44b873c5a464ee26a5315ce1b09fc40c26f32ed17fdee28fc7c8178e9f4214550d341ffe3091f86453469cdf341" },
                { "sl", "e3a1831b858a9514585e6156d2fde5932908a4e390750920a16d0dcc1a58a563361d95f0b612b701bc943afd9f9c2d42abe2a8906d1c8e50b0ebcedf69745c72" },
                { "son", "7074e42ef433e56701c13ccb33bf2ee18e80069924061c781c7c5f83999803fbcdc7f448cf3a2d8f429bf9ff4b0e5606f2c744c6bd7535d5d675584a6b096d22" },
                { "sq", "1e80b23f26f64f394c9e841ecef1e85ed1ee4479ef10dbe89da075b3847cd993b0c10156dc8a13a5b1eb435a296e39b4c2e13213bdd13cdc1d517a2bab58afd7" },
                { "sr", "4908b9d0c2dff8017a05a07d70db1572b0253b621ea9c408046c799d0c31aebb4bced23a9f0315a50aae03e2d5540458fad706c582a4d7ec24d129cca79c84d1" },
                { "sv-SE", "ef6388c98c7fcbbaa2bb21b46445eea0ddaa2e4f77b4e52ffa041726cba80ec709dc3039a2f500c2846b51a1d837b130822646994a911bce2bc8178d8ef573ab" },
                { "szl", "a37fd293f5689e99c1e7b25a3ade626a6b1e99dee55501fa7ce7704845eab1759c4b8bf45e3aa0b4cdbe200f520adcb26c272fb628b6b51c2f70e21e5d4c55f6" },
                { "ta", "58bb52862b3ed40376ae87461b30c4abc023eff0a959b14de38523c7cd7c8c5ed89f70a7e5649d440c97fec4c7cb46798046010fb295084cee30fcfdc23c05ab" },
                { "te", "763949396bfb38d5e03a448783be99ff422a6b9f092f6e69ea53902416165ac8ecbd8264c77cbf0dc6337ab0a43c445c629eb770ac23e4b01699afa3d0cd7c15" },
                { "tg", "27c5151da77c3ed88f5df4e2bcda4078f8879352d0f8c568d1ec9fec315a33079ec972c757b9c85abd18c1a4e6adf339c34519096133b4011fdd7f8ee566a826" },
                { "th", "08b2415648f1779ee54e1314202b5f73bd96f9d2e2b47ad56885c4a7174d44a9fe24eecb113b1566a4f17abb243299389d54d3f9971488de2a5b91719c9e3f44" },
                { "tl", "bf07513d8b77569b51678d34fc3578050a1087532104b4e4d6ae1c41e6fb7a915486ce5e12b1fac87617aa2d8bfd4d64e8df7074156379b627d4969affcf682b" },
                { "tr", "c6bed03d25b5dfb55829184a03083052c47fe6a3183e750bf7dc930977e8dfb7177c18ff4aab0421e04790cdd73718ffe156441a39a827b25e4fc3c34ca3037c" },
                { "trs", "0586d73f380d7408e52eebb6f14d661f4d1a416dc493f37c048b9194e139a56d0370716fcfd928798cb8e1c3ec65e7cc7c9ee8344e945c3e8163ee3e8fb63d2a" },
                { "uk", "269583b3f6a431eb5cc7a1dcb172b9dbb0ffe1de1b7b359375961a8e1492fcc98f41e1f7623d7f261fc86abd7d7ee466cb21ffa77a5fef9452183a434d287e88" },
                { "ur", "0629886ecf20c04abac9cc50c8d0beb2cded44bcb637772f11f75e9ecf210b3790002bacba0c7a7b0f258cf46b0b104c2080347eed8bd909951455d1ad90055c" },
                { "uz", "ae9cd5d2cbc7360e0482ec3691a1b1ebd891a9c97d619bcd7875d6a451ca108da70238c665f1c5e034f368804f7b143b27e6851ad667136c982a40534369b959" },
                { "vi", "7679c3c149ee329ca23e511c8c227cbc0b2de2b58c34f701dfc151558a2b203e538050e7545f3bf6713c61afcfd81d079b6b50c44894a14dd95dbf0957b5741e" },
                { "xh", "1c6df7752f4efc2d6fece702bfd822070de8fe2719fd00120dcf6c537a0c56319c7022b76cbf4f1ed823cea94f1630d056347f8d97f48f59d2b48e260a42228f" },
                { "zh-CN", "5268356a4dde5816bcc097be491f73a1ba5cbb6dffb36d0f9c3d9af69c16dec9162ef5f2a425c96e72eb06e4de09da4a3d4b32701aae5a4c5fa4024ed5dc6d5e" },
                { "zh-TW", "a7f5455ea844288212614095cfda1ff8ac1e974810a0ac07b03496453c2d1d932bb3c0cbf1c167cab46fe2483c1b32e380ef4d595e6d05cae2f52b923a99ec73" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/143.0b5/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "ee6c95e8c98c82c6ed2cc3550ea1180c5c0559e0b25f48245d0e12dfcd9e992879a9e46adf28136fed3d828edc9885774c32bae0973e3b7b2230fcada1aa4fc2" },
                { "af", "548a8be7277c7a5092b88b18fefc13f7625ca9be442e2e93a508decd341db670c16872df5a90f32cfc5d26365a0206bbbb321b1039fcdd6077083013a7b0fb23" },
                { "an", "31e8628a20a022c42bb4dee35d44ff3e9483738f2c3d36b23865418c1f425cf980b497db1bf940b25e01bdd3d410669f62310aa4ef5d7f3bc169b9d30c947178" },
                { "ar", "1a221226b6b90f747644add7bb67d87b98bf1edfebeed1aa07deb621e6c487c051e44008ff1b9d65682cfe582dfaba9bf060c8d39ebf96a6d09a75c8143f61cd" },
                { "ast", "5a1cf964d49e479f4a996d454cb333bc339489c59dbcbf63fda493101b7a48827e84ba44c88ceac0a48288282425e565788a084ac36371999718864b558ddaec" },
                { "az", "9a3c6218218cc709c827186812d0d5d3887bdff692e20eaff089c3def87763d3c65715483077f63b706e79f2b24000b36916f553278d4ab267461652d3daa345" },
                { "be", "6a6ccdbc9d7079280484f8b4919ea7c9cfed719db3fc03e3a7c222f4b8f0b902a44e2b75a36f9483b780a885d5ad67736d2594a04921019151603df78c6620f4" },
                { "bg", "5f8e24c87eac3aa4311733b120b841d113e94c7805b4bb7c31f523211b12083ee8ba290952eb043f5793f1d9660625a410505fcd5245ae69adc3d255efea9749" },
                { "bn", "46590c053f8c8c4f03115422ceff47fa0cebddbee43b5aaa2432c40eee80827b107f456d1dc48b18ee81d51dbc430d20d0e8d2d959ce24fba965d89273fa725a" },
                { "br", "1dc8df11cba95c3a8e3db0eb01af1183a9734aa6df34f5adcdc884b981655cbff91f287391f079c0a07127767b1026e5791eaf3a9737b938b8c30d54be2a281c" },
                { "bs", "0de0d7d4ca9a103349e2d9a68c16fe15eeb73a022fbfc6b73c14ab19252a8579a361ee85248da727991fe4700de8a7e4785f12fb861d264977ef0b6054056317" },
                { "ca", "8953a81c66dc16a92119b0b7ade424e2d43af56043b65fe039163fbdcd17629f78129a8cd24c65b98ca56c1389ff18ac3040a8bb06d6e968b6fbea7aee8dbf91" },
                { "cak", "aa6698834b48aec98175d0664fa87e54c1b4a215d6878df32076fb30fb8ba8d107831abda516fd10d1905f428bda7aeeb8298a6765b562f30e38a52b113688a9" },
                { "cs", "3f16946d81eabda1d1fa9870cedae4f688273ef53909cf53de44c4575d566855ea5b06000b9e26e726e50b4f5c80112edb2ec68efc4672d3333d356a8565fde1" },
                { "cy", "61be38602b856874176759e6dee9d54fa596ee4e83f3e547fc127774f5bf87e09c706006dc3ba1e86c455e1a079f3ad5a0466e0359a4d4aeeffffef78b2537e9" },
                { "da", "d13557b5e23594dc8f6eeb23b8cc43c49162b4aa23b8a16c4a9c5bf74bb787029c0c9102fb8122aab704a526a71dde85d303c893f4dc521175cd3b037630e806" },
                { "de", "84253c8fac4593363e389c18006c97aabd83a06b396b2f4eab8710c167dcfcf0d288e52976259a18957ab238a181a7a2dfc997ec6c88f01df8946bdd1b948b8f" },
                { "dsb", "697d4fe9a590be70d3e93c46d86553948f5ffc01b4da203eea0ff4185ab7f0df19af875d4615cdc0da408e47483e40bb80313b640bd0f9062bf79e755768c88c" },
                { "el", "8c15bef18c901871a762800610e0261f4e7837f2c25af47f80fcd676f0b0de51bb6baa7742b999804d18b811ceda55532fc0f3717f430a208d030bb650b5490c" },
                { "en-CA", "dbc4db375dd8e477d4a94d6eb070d10466878312469daa79ca5dfedef366109d2c8024edb31b84808f0860b35c7d0e7bfaddcaaa2743398f225d267ed2e50903" },
                { "en-GB", "af851ca204eb90ed9c1e5486a4228a39713e2a4fdf287a0d8265648556991f19b3b0d0815a334d0f85c375ab712542100df384d72d0282d20390c147eaf61b9c" },
                { "en-US", "082ec64c099c608af68b7dc1f58a86652d38b46ad61144e1a67a137b68afba0239ae81511ac1f80cd52dafa1d262d162cace310f84218ac47d59089ab3bad25a" },
                { "eo", "0585e6d397d1b3eef3b7bdb89996fe317d0223c34df14def78be6b6b8c1de0ff0355de4a03d5a4ae8f48ed4c20313275eee95b3c17fe833c4eb8fbcb409a6968" },
                { "es-AR", "ac5e0947825e4b07261c4ad3b22c1077db74f982eb449b738635c9b1ab9110c14f7c23e7a9848062374a88ab6d31632bb560f268956c07b2c1a221145fa4a1bc" },
                { "es-CL", "227368d1b0734b13da68acaf432bc40d3a56b8c931cb17421cdd209ac6ef409441f9ed76b6026f44b464c6713c42ec42f44f0b82e4e3d07e41bcc04136523afc" },
                { "es-ES", "d782d06db9310c3ee7f30b50fa73b842572b508a01cfae0bf5389a177b524cd73bca0cc424f753fa1c14a5909d6227f6b7142047ee5eac798fb390d33751eee6" },
                { "es-MX", "591dac88f3ad6a83ad5c1becbc27674002b55ec1ed5ee27d9868b5e7743444406b3820040cc234f5e94752b53441953a86d057389345eda03f1a04f4598e4b58" },
                { "et", "61256aaef1e000e7be218e5ef64afbdcbaf3f26f1d7e888ad38c4fe746df4a64dd3d00706470db4a4c361abb62f7d29676aa12f6c84fba679d5a5f0934fe2526" },
                { "eu", "013a33b6a00edc170990035f06b3c703060d5fb6b34959eed3a3aa94acce7604f8618ba3151818f76caded4cb52bc174f506d1070a8fa332f3e519185641c0bf" },
                { "fa", "85773e5e883b46acf44b0e883dc157ab0ef158665ac08bed9be87a0b3004ca5502b6f0bc5dba1b5dce7decd4c32d53a6e39f2f738a0ccce8809156f253e4f2ec" },
                { "ff", "481d868a52fbf16b2272b5304e68ae140cd78a04fa45044fcbe1e4ea8fcd47adaf8e1114dd5c95c5baf9fe8daac682a2859c148e6ef1f893b9413c35af6ca8ff" },
                { "fi", "2d1a533a53a3f08add791dc8312b78baff99a79a4ed3dc1c17ac9a9f704536a7d5b2ecbc230513dd597855a470e03120d558a005f0c672ac3c55f11a34b524c5" },
                { "fr", "4200360bbaf00b21f1a550223917585dc303d755cacf63b00b1c04f29dd2fe027b3507e8fa329e8ac2da511310aea1004845ad64bcc052eac418d872d69495fc" },
                { "fur", "d8acbe1cbed8deda39172cca17f423bf81cd2bee531a479decc09557bbef53bdc12ea0c9e298297c33687a7e5d30cbadc44718ae3b4e6d12e8e717114172c164" },
                { "fy-NL", "69a11c392866c85da6a8d93f101bc3b5d89be571a69ac413bf13f7019ed2a9799c8e6d5bbcee4ec2abfcdee41573a8fa33c90c3d9a7de158febb5f97af22d24f" },
                { "ga-IE", "43874efdd61298ec990b56d4ee774d4e75a2d32ea6fed7668cb44dd1be253e566fd37e4f4ac5b9786fd61521e8741971cc4e2d57183ee3bdc5500c60ef899b11" },
                { "gd", "a24a3e468991c7d966e00da49c454690b86fcf91c993ea7ae8f145cdf91e8d11611cac2b62b8d7d94b13ef55b4f6896bb1600f301d8bc0d3a0bd3f6294e76c37" },
                { "gl", "95ff1d535482f20c195c407882d351e5fecdf9b1b783040f9a7c18e920be74cb781dee5d91af08a72f4243ba1214d223536b4c4118ac7d315586d8bcc44a6c80" },
                { "gn", "8613ddfc71f81014aa132df6e3574385b418d5839ab813642c68a3b30d2921cb2abf24bb36b26a6d39dccb983b0325da9eafd206a60dd0722d76a26dfa6fb3ff" },
                { "gu-IN", "07f895c056ad6dd611ec38386f4088b8632d063e29bed7251dc09a09cfccdc7b39a431ef8876f944e7a8aa47f2cb7b2fdaf7f29d1f3ef9af8b0a0d8a4b3ed522" },
                { "he", "59bf96329eaec4827e107fcf198aaf9b78e9bc34d4f33f3864bcf8889ed8bbc5210f5420b40497d2548be1fa5a46cc345e18ec37291964b534d31393c30318bc" },
                { "hi-IN", "1e3c60c9c7f3ec8e19224171e8238a0b055463eda3c2c3b1086ff710c8acf8588ddb7f344d40ad4ab486f1f951fd4b0599209f2c31ea4809eade90d08de36fcd" },
                { "hr", "bb07235b99f6664d2031bbaf42224e34413394470352aaefcbf22a75d9931a4ec0ca381928078eea1aeeb2fa0fac021829b728fed4d367f7b95457639e5523b2" },
                { "hsb", "7fec66c322713a676f304e08cc680f3f3a21d3fa1ae1bd355bff3a4affa95ad0703ecb24dfd9d2370f043e5619645a1e6eb4bda3714b8f836182b2d57af03878" },
                { "hu", "1793668dda5e09435056a4d8c89b4e00a08d720995e5e68b013de0a4bd7960b2e8f43837ae5956069b7dd7e2a3016e0863e6d43717ebf081dd98feea0903f08e" },
                { "hy-AM", "a3a415945f8efaa3e6fc99466ae61d6e6090e44a0b09863bf7732003e448343bfec6e9cc428432407a00de98fdb89d6ac230c718fe2cb75a1f6330f866aefa4b" },
                { "ia", "5d5c077d3e11f3467de8ac0289ad9aee11bec5de1f22aa303e15de4c9b298e49593489836c8d737eda005a8fa60406683bcee1c264a9e1e6f9e5e18cc261c927" },
                { "id", "c3a03953b12bee0037aa33667b82bac877432b4784af387ac4cf6c623d3fad8568cfeb45745f858eefa8100b351004677d251523a676a0878c1c1afe6c82f5bd" },
                { "is", "62edaee14c598d55f0baa5decf726d55e60c6cb75b46438650065a6ff43d7334bf7e05b1218ec2596f6e7c257c4976337cbcca58ba31bf0de356f42ce6ea4638" },
                { "it", "41c5576f566ef9ea1560ba85d0ddcf2ceff46a8f0c6ed7d526839b6dbad74baea55690aa4d389a84768139e0e9cb4a1eeba7c905c60712fd06cd88c098ab0853" },
                { "ja", "9d1bbbfd0bae79d36991784698d14b3b501a81ca9186bab23815ac23b23bf7bb654eacfc310fea36c44a6f76bc85b8f6e129c9c49d83c8fd87b56b7c53003845" },
                { "ka", "8cc4768dff3a0292fa01f2bd501195484c3a61ae959a982920b082225f84424047480c66d322b645f7e678eabacc7b433265c7e5d74cb9be57e2b4c0ff5c6238" },
                { "kab", "02ff01129f0e2c9c6ae096a75702a839459ca4039981f9fe1deb95e2ec199dc5a9e242bd0b40cffedc0750a7bd6befa3488301588117378161634399a04b8885" },
                { "kk", "69223eefb8496bf5ff076b2df6ff2e3e20ee5569576a61e78d30dbf87f60922119c7b4f25c7f6d3f76711ca78e36d8e8eb4b1412e1f496b95fc86f8c6597590c" },
                { "km", "8dd2d8036328f8ffdc82292d5ab639f55771b73fd871ac5e2bba6ad4ad7b6f7c4247b38b3a193d01bea6cc3abdc22f68652f0a5e4b3d3a54b74858cc90ea816a" },
                { "kn", "55017bfbba00c235f23fad9de8b9eb4648302cb3d4b481334891c3ebe4785937cb51dc5103ce93b1355980289d69cbacdc73922931e22ab2ca49c18591834266" },
                { "ko", "4c5bc646079f1a4836e1d02cd6be953b5a05db5be3b6bd22c6030abc66bd586fb8e399a7ae019550b1f6f894876889739e232ea451b451976fe696a24341775e" },
                { "lij", "19873f65bebb249dfcab2443c4ea76d25c59c63e7e64d136a7d6effe5b3f3e4ee64ab20ada91cafd10dacb5dc928242805dc77ada9c17fd4f1f68925f8d3289e" },
                { "lt", "067c3d2c251f9028811143533c5117c61731535a23907af45228c14ed009e248fef7fd5767fc70995b1b42c5664d0356a0f2dce7ab1e29334905592378b868a2" },
                { "lv", "acb3cea853d1aa95f691082524c86f7325b7df6d163aa49a970cbbcaba72bc17acf9d97d47b93892dda7922d05d183cab5a5b4b247179f03d62312721b0468ed" },
                { "mk", "b0fb3774c4ed5ea9879a6d544d70b94f24387521c9211947c34a5cfabd239c0270338ed8e6ecf2a58161999d6561c58b5f3ce0380f41ba8db296b09ef8dd76df" },
                { "mr", "50c91cf6844bba4118bf1ee6c0e2c83345f7279f14403b6e8e7bc37225d6f59e8a8b66f4f85d9088e9b0724e1e73f7201f13853b3ca41a244f35d50600279238" },
                { "ms", "3ea72c906e2d6724871421792112612b74b2511b21b41894b26af56bceaf78208897e77091923437b1204cce83ed489d60d57a49ae5fae887cd7cdb38284b2f7" },
                { "my", "fdbeef0c5a8f35556a032e69f5bd8ad66d45837e2d6fe9e169d095e46c0b1ffdb8ff66a7af68bc0d47fab7e46eb070540b36875ccc0ef6a766e7ed4c386acdd3" },
                { "nb-NO", "09f5e204594ba102c2286c0cf67bc997c8f600fe7712915dd7e770cfd12f687ea4d5869472e1d79c25515e40e5588a8c3eb691976893c96c44ca236fc8e5387f" },
                { "ne-NP", "5a3cecc3ab490a4a2a9442dfc896223317f789321fc0dbdcdb543acafe6372179eb73518c2d0ef5c1abb5ab9de26c76eb901c49c8bebd9f17fbfb73645585e9a" },
                { "nl", "f891e63606e39aa4cf4f99cf0d034eb796770c331e299e02685862f57886ddb42ab457526598934f91a86e279bc238dca861e17c0f9094586817afc1b3c7b523" },
                { "nn-NO", "911093efb95a3df73fffd14506ef45f64b0d85bc9bc294bd3bc5de77e72804f25d9a8d89ccf93068b451afdf1da97522d9104a63f90aed8ccd7947b33002697f" },
                { "oc", "5a3f824a90f4cda2e0c785f9329a907aadf6f2591e4f34cfda169525dc6117d48236b35cf57aaecdac20f9d5b09ea4c4627a92a8e8cd7db2f18d23bda5b9ac10" },
                { "pa-IN", "9956c9af90ebbc46eb2f484520f345a36037c652341b00250d61751c9f7172381820b9eb02a72ce191d31cdd7b017c3a7b9319262fde809f8f9a691d7cb33958" },
                { "pl", "0a62bd210ca915a07d02dffb890ff3c1f331de6f685d02bd87fa5e0c0f4fa3f282641ef1b1b98596af76ef6f36ffc55076a3637d1c43c548550ec4a49bd6fbcb" },
                { "pt-BR", "52d11f45008ba2f3b09426f45956d1193adecbb24a2ea3611b8ee9ecd054df78d43e887ae7309517322b0df8af7465bac78c2ae876dfd973cb30093c02e6b4cc" },
                { "pt-PT", "77e2fa81cde748d15ff2ee8a7de3013d7b0008bd6b52e68b5533c1ccc67fe3b9898a5c21ef3058819bc2bfdcc52e4e88167ee0a34b25c0dc02e9f88a970fa7c8" },
                { "rm", "83c7e99ff34a59d2db4ba330881156f7f672b2117329c7095ba872b0d0e92e573e7f1729be9f738639a37ed0f77d71550a7f903b9cefd6ce8bf6ea9d17e5fc5d" },
                { "ro", "fbfa081d61c56ae45374540969ad55cd5efcbd7766e83477f47a78a6e84d73d316659d8c118b83ad4d615b637f9eb203245c8c8051fa30948c8bd436c66916f9" },
                { "ru", "220277754633369b9c05a5b90a45724cc8acca0f7b833653ea98ccfb6b4e142c86bf8444d9ab6d6ecc951572dd8ac89326570b5c184598a3898375d4e8900ba2" },
                { "sat", "ae12d63fdcb1db2d078b720eabe7f6c7ee95f3b502fbd37d1190fb161349014594f790087a39a9321ac74d0be98290b0a19f531eb28a54ea8a00f12733f0785e" },
                { "sc", "40fcb4782ba9fdebca218807e37f56e9c08d1819d287edd6c20496a1a8fff823a5a83fe0ce2a89d2625552c7b93fa090b42622d505249e539be263493a019ad5" },
                { "sco", "0ffa07fbe67cbde5865e0655644afead2f0e6a13a909f77ba3c06f979447b61c1765640db381b6fe30d15991d11de0491eb2116b90daf39099e9f1993b735319" },
                { "si", "45327653cf51051c19a4a45aa3b40de553ce39ba4f1db9a32fea20c2036eedcffda706505e10941f60c95c954d3410fd3ba052032ccbd657629666abd63ff79d" },
                { "sk", "bf244a7068b20bca9c5c90b9a3720e55a47a7bc5b6f177b440eefc46e3f894b094913eac42d70b15ae0b247dadc243da639d41252e0d060a079c38303b8d7640" },
                { "skr", "5a7b4981008517a8970cce06d7ff88b03efd8c4b58beb924536593025eba6bc8e8ffd5306429b353504b3815630c1114429cacbf0669842330cfa3f80b7cc7be" },
                { "sl", "dd3c014a804022cbb3f5e3a59d85ca00cd5989f820f01e40c00dff467c5033d906e18ebe9829bd27c4e8c49ef52de49bea86b8301e656cdeecadc49f827d317e" },
                { "son", "90ab864dd3ef871c9254b51ff57e798bf29b9ab4626eba493ad438307ff30ecd6acdc612e3dc75cb2696bc9539e61872bcf14ffe1fccd9ceabc4595cdb789319" },
                { "sq", "72b0251ced3f01879cccf9e58822abf7c74871ebb27b4eaf8178afa25de03a8ef33d632223d8f735764b101a86ef10930e821989fdca49258f6fc010e9d1beeb" },
                { "sr", "a7a80fd9cfb04f6fb35be2c05384ed64b8843a8280026d554058c36b9a10e562b2b10d6f3ef38fc3f6c1517b3844c99ce89dc31be4fb7604cd9a042b7b8efe57" },
                { "sv-SE", "3c9b6bad4277b235ba290d808939eeef8b924d73d07cedb80bf0573764e15f918b55e3a39593212b6310d3e3772b513c8ab212093b031fb7b693fdc7c8c7e416" },
                { "szl", "cee751840e2f2c0929c3e410f15007356a60a6bb7ff28544bcadd58e09f10a805cc2a90736890c02272023dfdcc3912124447d546017db46e6d616112a135e18" },
                { "ta", "2eefbd5326d956135d023934cb2e9703930828f68e1848bd502b50a9fa53fcc56b0cd1267e14834bc2bb9b0681dec5e2af079734a9adaee136b617197ce1c200" },
                { "te", "e6e48bf4138ce6cd0ab525e874c69941db59dce8350a58ccef15aa4174978d8dfb277284129b88dbe6eba4af3c4739728122f442cd2b7ad1c2185002cb1869ee" },
                { "tg", "23d3f9ae19e7c9997c11087814da36a6e9b488eb823029658bf753f78ba282f2ceb56201d8ab4590cffdd2c92d5e4c31e268ba6ccaae3f24aea3f560eec2def2" },
                { "th", "1549cab00e38baac70a84e79c2bd6ad03356b94efe22a0b8643738e71f876a8cea77c3033119258281f38151b7ff1ab3b076296b69eb981a22b5c19216104ac1" },
                { "tl", "7ff54d3070148d946fb5723c63d322b5b5dc154d0db00c7776b4cd772829726081db3404d2338382a42e1e5ddd1b7d6592e6bac1423f435a801f3aa774f56b15" },
                { "tr", "d01b8896884ba3382d7ef02af6bd6ddc296907d78687fcf6390d590091618432833a9811fb9924018a78408a896794098d3dd974cea68064b2ed1a100333df6c" },
                { "trs", "e19864b6d2827e640ee61600ceda27e5cfa797872bd896a475ffe7d2b245d6ef37dc490736c5a5d474b7968f1b9067c9e462ef89424101161a32e3d6e0190949" },
                { "uk", "6f9a8708a661d8ff706941a9db7938251c2e8954090bc486ecfc32a692adf544d233e40d382bcad358c59bec8e6b424d08abd4efdaca6e1d5354664a5a8f68ec" },
                { "ur", "519284d4195717f92c4f795f040d940d1c076a3c6f0cff98f501d4d3a298d4d2a3a11b4faa5089452887865855169dd78177930f8fc0f2e4d0df8625a09c961b" },
                { "uz", "35f364afb3f163c8ad95dc2019ad345903125883ed6ed344f665ef26aa5b5ff0f41c9c88147fba3cb2f54775c9364e190f0fd88f5e2b538dfb49d7c380564b68" },
                { "vi", "2116cb94a652c1dd2e3dd61baa76c146084cdd6184923fc7922a93829f06325c47c3e1f5b950461eae3ada7fa4f65ec8d6e2962c331cd41d6b79084ecb6abd57" },
                { "xh", "dc30e2e052dee0053290e03c7b677aba5bc2bf36ed7c76954dd0216a41a5f8d6c141437e963c40bae8292b30f40781b95a8b16fe21200de961f10b23ce498cdb" },
                { "zh-CN", "f11c997355ef02721988aaf6cae0c12940b22cfb9240c4e584d4fc5d0c14a9204ea525a53563fe120849b9742c7b7c9f140ee5b62e4b7e52492a2242663e8b0d" },
                { "zh-TW", "45edf8a775aa330747961b656df6b8f37fb748ed91186fba204b15eb5d4026f0e84eebdc6e9ebf3032dda79d5adeb908ec4b8dd36357ba5b5a6ce00819eaa2d9" }
            };
            return new Dictionary<string, string>(102)
            {
                { "ach", "28b40089d5e3804b910c9bab4f0a32ac4a1d4e32a452760253c08d2a08bbc24eacabae3de1051085cef00e9406063317316283d08709519ab39a617bcfd2d6d5" },
                { "zh-CN", "47280b09545ba147432d4a0f4545e59fb4f7f9ee75b39fa7a3d53ce9856add9ef964dd5d2951ec45a1fb19d853f9002a384cd1f5cd777d8f9196f0e483e1fb37" },
                { "zh-TW", "00e461e82ff62a7a00f6d7823c93e99b12da69920c8dd60b00039b7ada2c5e6b14473fcf6f6a9b11fefbd3f971def845ed3dca6d43ad62b435b5cb79d282e9f7" }
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
