/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021  Dirk Stolle

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
using System.Net;
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
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// the currently known newest version
        /// </summary>
        private const string currentVersion = "95.0b6";

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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var validCodes = validLanguageCodes();
            if (!validCodes.Contains<string>(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/95.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0a36b267b181f7d66eac87bf5425ea3b2b5c5bdec764cf81bafef1cc52331fb5dcf703a9fc77b603483115a0993d31cafff7afa1941f8d49f7a089c3ff1f1a82" },
                { "af", "41a20cb2b868b737753367d79588943e39507649a4a789fa996a17fbe575a3195026caa2c50ad39641e463dcbb8fca31f4b26b8ee83f072c0dce5518310a7d18" },
                { "an", "a319981f0427dc0262070a956d4438738f5a9985221fa0a2e045b3b974b7c078c83fbc2bce7c0134a7c495db10b8d60e65e6b85cb22d1bb6cc30bb3ae9e5876f" },
                { "ar", "391dcc4c6332a9c22911633a790f141d23365cc6a1aa0c868ac04523c8192ab259ebe57f081d6bbf269fe94f31f885a3b627ea9a012d1ec5a31bbecb947f69ff" },
                { "ast", "b011b9b51590332d13aadda6a8eae8f3aeb4c7caeecc10f3ac927d76568c415854c0a273617008161b6b48838518cfed44f9601cd9c3db6dff600299255148a2" },
                { "az", "99af1f25274ffc3df0cd6637f6d27d38456232ff11c0f4c98ed93aac64c1f6795a88b57eda1024c5f9209ae808e22c3a6b5ddc01e80df934e0a19e421ba9a346" },
                { "be", "0f79635a3936eea8f96fb95b175184f075c5817762fa4271c3274a36aa35408c6661132f0bac5749f4beaf2eeef4d3758b1db44dabf50d646dcd606ac02f2503" },
                { "bg", "b7a20434c0c9ef4150ddbdf71d640ca929f3f9381684dffbe7f61c6cb41de810fa3739d5366653a113ac4a92a661de781a9bbc8d271bf7e35e5fa6f384900b81" },
                { "bn", "2fca3376be1ed48b29ac794c99086e8d2198f64ec9d77cc0be8207e8404c8875c2b53f73dfd5a89a205a1fa7499ab2bd10cce91b4e8b34ad775f4e2842b9d21e" },
                { "br", "9f0c7f1679f22f60ac3ef5fa5bbf482513e47d57f41eb5dce52c7654216ddd607182fe83f3f2f8d434b9d48e245dfac1be9f3e7dfbfedf3b871986c14da6488e" },
                { "bs", "f95c5ddf2595f79c3c2e32b9f1abce35e8e4bbb433d8e95372cbba22a379b43b440bb69d2d48fa469301df8da8d495d73285ae74d136c1f6862dfb7be9463870" },
                { "ca", "4820d18f6bd00fd4e5cd5b627c9aa8a2b70995d4ae64397a2ffe430607653980f005be127d2ec4d7ba2d138d05b791be2258510b2d47aaf291a62b57050119fb" },
                { "cak", "17c4397c3a305287048959e16faf9b04045dcc87b48c87b15ba706eda39c8954c4ffaf55f490a75def3d947ce6754749060775773a24c06134cf1a2b491bc8c1" },
                { "cs", "b165447cfc612e7b3993cd65b1f1fe4f3696d70b1d0e967a62d0a607409462c6b1c5ad7d19b7cdb968885c311dae5d42e2e5b64c06ac4cbd5da20b9ec0c51aff" },
                { "cy", "76e56c7098ef2bf075df5811a122c4636398a042919dc65a991de69e2c1b91d450a4d913b5c8403bd7c570201b7ca8616fb08d7f75a57d7fb2d0068b9c875362" },
                { "da", "4809ee9a5b5cbb1ee21d221506935e62f5e77bfad04ef541a366d8b14ed39aa50f138a0114376a34352253ace7b73b1c945a88ee04eb1cdb246960942114b658" },
                { "de", "12de0c4a4ed30c500ea040bab2d246bda263a1230c7864a768c76936c42b729fbfaf862750b693eda98d442a3e2267e293d0154c61b7d97448a3389ba6da5309" },
                { "dsb", "d3da98fd74b02db80484844cc9519f22049aa792ab37fdfa81e3e6520efbf6e008ff34f462d418a4bc26dfe7a2aa04e676fe5877e1e8522ae235682d61c9380b" },
                { "el", "ba8896bf0f5b1934fb251df73229bbbf8f6a9eaa12488afa35140bc4ad67567d013423597f9e686e9f319ce2aae3dbd8575f6c85de5a20f21762efafd8d89212" },
                { "en-CA", "3d5cda5722c6b6f7bc9e13d6c61ba85223eba47844259f86b733a9d8ca597ae2f5580aa1816473c4b7d6cedea387c6bf454071448a52706f5204a1ef9f3a173f" },
                { "en-GB", "5b1bbb454b83603f35e985991182f8278337cc19d5bcc7837706a06be124f7ae87088bf920d4775e5eefc64548e9c15a7b9cd42821c5b98b9b359b626f25a176" },
                { "en-US", "bfacea246654953e9a18962ce949bf0895d954ef2884d97bc49eda5bc6bb84f546dbbdbbfe002b71c5aeb471faf57af1d6ec21581056e9fec3fced03accfb958" },
                { "eo", "662337a78cadabcaf793da17cfb9b63322f62a109fd2611ce2b122e634594d16c0b1ceadf3917d6fc04641f689735e910723a0c49c910382bb4e248f2413929e" },
                { "es-AR", "df61762dfd51952d514b6c1f616b025a7ac0081a1dcc4569ddf19a1d0522ac67193664aa346203ce2762080d4672e625e9ae9da75f0dd0371f216e46cd4483e6" },
                { "es-CL", "53cb7c387c2d492f700b4739454ab65bf5c119f24715cfb71279f266fccef39d57c7734f6d10394f0a58e7fdf97c34a59dbd26d618e98b24570c3de57cf173e2" },
                { "es-ES", "718f57c4595364bd355ef6bdb3d04ad39a1c8807e39edcc2733fa14eff7bd1795c855c60010e73f706d768e3bb628b31907d684433514faf15cfa7e24aee31f4" },
                { "es-MX", "2d64284b7bff7025a892767a41812909c6661438d76c039edc1af2885a0e9ec6bdf2931bbbcd4720d05c265bb9bac72572423afad5134bf6caa64b56ad4fa8ee" },
                { "et", "baae663ede8d9d69bc491238071a747e4ddfedf69a9b5958975728c76a4da27bc4a0658026c7de5e6b244940eb6d68f3fe036421630e75bbcf001bc1960430cc" },
                { "eu", "90b38148d000902ed0005c0085f6923788004423efe87b68b039415b88b814aee3e13b30285a16ba953840e004eb4e8dfdb72edc22dc947d7e05ed42bdf7fdf9" },
                { "fa", "3d9d3528cf98b289bf9264cd570c7412d424c9d0bb03e56c58e6a63bdd9f0d68486df8ec73f110634c8d8243f04d2f2e1d29c1b2d2b0dec059c92ae2261ffe12" },
                { "ff", "757ec88370957cb20b155225ad76ef1ae06530b819ee0177aaf71fa47c9c36370b1cb814fe434423995246218686998903d2764e826bbfb5e30bbc1f29554fa6" },
                { "fi", "f0e902fc971f06ae2481ec63f128ccad968ae2dfe05a3c52cff5f31d5ac5ae0f1f3bbaed0847773c00447d66e404ea995b2969525927698219ddb6c8916615cb" },
                { "fr", "5db3b3316c05faa40b8b312bcbb9094d86b76c9ea43e9a3aeb1b8b821b535445402735fd72b437da74b4efb13c7ec687c370046cf5befaf7c859ad52ca397c00" },
                { "fy-NL", "3f0d8f06d227bef31a43993e2552d452ebb7b99e52bd18937a77511a0aa4187a163fa81cf4efb7f1f9b45d090b535117207b6524976a8bce989ee912645995e2" },
                { "ga-IE", "4a73b2538e095545ddbd2c42cb782c5680899b8499fa3744eec866f75971e9dd9dfe232c08749a30eac7fb59145d21d7c45f3174a3ecefde863b31e23c8c78f1" },
                { "gd", "35ca41ce14b5e38e1e0517eac6bbb4709f11429dfb2e62fee9184fbe91b22bae705058373ad0782656de650c1cfc6d07e25f4a1d8d36d956ba7ab2515c05d32f" },
                { "gl", "00223ceca65a0f228801412dcf6a36e8bd93587cfef2c907f39ac32148b11574b4b0e7bce7174b54bf1b795de4f313af678cde77fb490b325792ff123719e97e" },
                { "gn", "450d743003710bc7bc3e6c1b6db865cdf69c2fc8f71373ce1635302309e8f004bcdb6612f367ebe65497977a16cc3e4356920cfad68e7d31880e945348e41762" },
                { "gu-IN", "4774ed69d1e65d3134ff3c078797169ff086ace8eba9591313d3424991044b693a232a1d96d311a8848ab9a67d3700541d54abce32623347204b9b45d488e6be" },
                { "he", "dce7d94fbeb5170de38730ef00692aad25fca874f4cb49f3006f289fe3ba9087d4847c4a4cbcc456d2953dc60efe04dbf2bdda029abadb24022ab531a70db43f" },
                { "hi-IN", "faec2602d5d45e9cf34604e7b7a748ba819f68e0b16a4d791576ca90e2f2dffe1d9d4fb34c13fde0433d706f36bcb0fbc75da339109f69f9fb3dd73e4c1c33e1" },
                { "hr", "b7181113183b05eab6861ae2eaf438a207b812270588caecfdf6cd69d41e5e66b886fea514a48bc3d8ea87f31f428d16a429c928ab471db281ef091ad96f1e2c" },
                { "hsb", "dc304874721e0e4e312ec2206b5d4e188e404f499505b5d4d3c0ad776e16698c040d6128a3cf1e0ef80aa51a7f171b2fc2890292b48d323b46d150245192d509" },
                { "hu", "31e701f33fa04b32525935bf3b09f93a6ed72da41ab2e4c51a5748a11e67983b6c9158f5fab479006b80f00c3d60f9479fd9d6478ebb9060c7517c48e277a089" },
                { "hy-AM", "e20172523359f1701dced1e66e75ccc3e86208f27953cd032dde92577bd18e2355f0773e351caa5308210c9c8dceb9092c50c12af5c2f6169fc5e0371e389ea7" },
                { "ia", "17b7016834def75e05155766f5519d1d4fb8e1d81f35c72387530f628d174c3638b3e4c4071b4f6a5fa1c8200e9213d2194b2aaf770bcee0cc5c0e594bb2de03" },
                { "id", "744b7d826148b0ec3de7722d667cee19013ebcc53184ac9b2a0e7c0b45dee8eae63660c5d65baa44296704c23d73b31a7572b2a4006d960dd7aa634219cdeb15" },
                { "is", "57dadefd07d8c0cc19c534cd1f78ee9eda21a432b8fe48a776a066f9dd01285b3dd1775216d6977c07e951e399bbf710bf754684c2f343f6aabf6ad901fe2030" },
                { "it", "65fd5a179cf1b1aab3992d951f5e58505b70e6a5a9e5cf24049239adf74c7947f20ec7b8d7f8de6769170ab49fd3d0ff9943aacd66c90083a430e8caceb58a19" },
                { "ja", "c14cc297574dc0c20f80658087e8849fc3148aaf50107460dfcd1b44492e5de18de03a6ddd53bcf3d25927f88af3c1615fa87337dd2cbec240e6d3613770479a" },
                { "ka", "7242e04e557501219f4ff5a2a57700d410266613db95fff63c62a8f6816971da924d722fcb2672de552e4925ed4177b26351b1881fdce9fbce12b47c5d6271ad" },
                { "kab", "afa603a51b09d29f0e9046df40c074bd86eac8a77cb538a5497e9ba44b10b05d5f5376529a61c50a4434be4c4d5cad483f1473186c313794daa2ffdc1fa41cd6" },
                { "kk", "1b3592deeac2d0d38f1a11381eaf69fb16707ce6264ce764de5be02b506e38c7b070b3c61811f1af670df5f482431dd40a484bd17f8b2d7e37ef0acbce941855" },
                { "km", "52baa7cb1110555770ae624eaa3396a7cb833efcf81b5cc1c923e4a3d818a4ef1415a93540b19f3de8e07ada5f7e2a4d7d4227a14cea3b26f054a652c870ec9f" },
                { "kn", "d5771b20ea52b576ba89212299f65e64758fa3484b0fbc597bcec8bb0768a2a3a9924f4db2d52e44f23fcef7dfd868ee441e745d7df1b11406399951b8db2cbc" },
                { "ko", "70f77ba82955cce8b1346bb73f04fea106671eeb4039170c7eeb16b38a3eaeb781404260c82f082093c60eceabdfef54f8c61053f6f1a7753f575cce51e81174" },
                { "lij", "779d77fd04d85fc1420b6df4897d54d9f7d3f881b25e6a7e96304cf2a3847c00d22d6105c5b883389745b9d41efcbe89accd6d4394dd57d83d5af7bcae393440" },
                { "lt", "883dc2ce54306826db73e2fcbc8583fc0d795ae92674b4d925a8066b4b8230c1bc5707218ffb9bf07d0dcf1c0eea479cf2680dcae8b69098b432d3a3cd3a332c" },
                { "lv", "46fc4e4f54d4d0f0110d20ccc0602b78c71e4f76f47670270702a398d8766fd576ec6bacf69b7ada1e70d5657b17191c4f3ed0b6d2b5b57dff11afab3dfdeafc" },
                { "mk", "11ead08b5e67086d6c33f5f239a4a1ff519a05e211c3ca721ed142695dac731ad86afa918f60c9ce06f7aae3e6808a04e7fcf06f0ecf553b1af1070f5b83cdfc" },
                { "mr", "2094d48fd92b2968c7c3212f7f9a2d2a4fd0b2a69393ca730a2a5656a6609a51ad6ab0b1c99d33dabd0b9d8e26f2a20d17770005b889fefd71d6ddb88ceaabde" },
                { "ms", "bfbf6d977a8b8bee5b8a8af90ef6d921c55992d58c6288528a6c45a30e7b16d4edc3d4cf0a51fbb7785a0b93f4511ad7476dfe1b46c8568e6fe588635b185c75" },
                { "my", "55691e0bdff08cac48d09bfbfade3a19e052df9c5b617c56e18533fb2078dbb6e13672bf0e7a8560c6f0b1629766a5fca97fe802ddb4f75f26bd4bd33e80038d" },
                { "nb-NO", "d3b63e87be887dbdd93d758103382b7f78a8e89b708ec45cc7d035f3c68e15a49a70d90d032ae71feb4dcaa0d962321152e9187423c5c19888fe8768cf027633" },
                { "ne-NP", "eb2e9046c719577adba103a9f85e3e361050cff8b3355a86057c16622d5ded27461f899c156487f057aa899d2600cbfb6ec9b1fdd901acc3480fc82734fd9519" },
                { "nl", "9a5acb180eaf0c2e7e6c10d26db9fcb250b9f324459e6c4123fc1e556cc0a304114b80fc44eade35f512711cd3301cd417dda2f17bdc7dc576acfc4b7b5f9000" },
                { "nn-NO", "70e637fcac0745752cede963f3edfd16192267c7514695b7b4bebe3ad1d27217529325214f60dd35f1db9fb2453e159b65f462753efb782d053db937992f01f6" },
                { "oc", "a2d06ba654548c0a388b9f6d050db4ecea3d5c9411557e21919742d8a7f15c0ef68b25f6a90271da13fffab58ca98a058f1bcc84f8edabc387693291497d9032" },
                { "pa-IN", "18164c3300d2828fc74bc02865b00d3066236b888d7025d4b4089991dfdf88045184c7f30342b51a0f65be5f374c713fe551480fc78ecf3e4b24bc3733b6f5e5" },
                { "pl", "e8ba9525613c30f43fc6ed096fef57b3875951b8e6f9d602a3452d8173f4b99990f6f3a4eba21855d1170e1a01d59ba6f894b2b2b0ecd35f1625e291ac0d2876" },
                { "pt-BR", "138384ab6f849143bc65d3ab64666e81e843b8febc37cfd9427362bda7d616f31dfb5b64e4badb921312775b8fadfe7f500d3370ffb0975fd8a68175e164524e" },
                { "pt-PT", "7c0abe7c5467be2c3ac883fac55fa1af2ab0ca262e64519906bd630e1d7f33972a3004449c466e0a5e88469d2e284b7670c3414c58efe16b60f0804ad2828a15" },
                { "rm", "7166f94bf9399fac7df5a32a0bfb11c6d5014725b59afa408e15b022585f469d020ccacd7a9320fb63ae880823fdeb541947022f50114e9b75931537baf1b7c0" },
                { "ro", "2eb1410e91cc060371510210304ea552b10c87641ef10b43a7546f6c3a15a80562401138ea421c1c6da1b609869ded6df60864c3556301e44c78639dc814ea4c" },
                { "ru", "63a186002241c7ff3fbb5cdcd310dfa43b4d49fc7187ccff5aa8c0441b75d3c428cd5fad1110d6f97afc73a7e6461fbd0d72e45592f4c104d770b5564ed24cd3" },
                { "sco", "a10d3dbeb4cca1c8991b1b5ef1f2ed2d4d530cd53a6e8a0475dc614bbb9242f2442902c72a7c1c0855442ee7da5e5199c58f660c5a16557ee81e42a55760da3f" },
                { "si", "51e14c21ceffe313b9eaddca5bc74630d45fd06eeac848ad0fcbd889285ddd3738dec1e13e141d5df4e667257ba794615048741a1b1657503954d4fe078565b1" },
                { "sk", "86f78323367a220c6ecd009a71480acbe6e7edfaa77510702dac8082004303818a03b41bbb83e2ce76df62320cf3436d0bd577ed3d0382923750adb660327546" },
                { "sl", "d1cc705ac9d9d9b2290bcedb91a2374dd026b61ebea2d78a5ac34741253db6cfc84de5427b0e3c74c28997df8580c05b43272eabc5cb84f2bfd1cf6aefd6472b" },
                { "son", "7c7529e55d5544c2e32060a775bb480570796aeeed0d2206d1bef1de461700657688203cfd2c18d8e35a1a53b88c3a0eb8037c13b395712fa723f68209335844" },
                { "sq", "20f266c4c6dfe4cbd16e5693f6c000f1e1bab4631e894c9132ada7fb568ae370a3fa483c0d2439bde0e81b83fd417eefc1fc87ddf475b2f9fd462646fa5b3994" },
                { "sr", "4537d197a513c3f62e89896b3dac2a3e99a66f043276344aae7fe0a2d3893b5f5a804b8baa5387779c34ba95c66e713764617954557d82347be6b36209d2f022" },
                { "sv-SE", "6213c9fae00e8bf40f774a3983746bacd167f87422070d062b954ea19908de83ef88652b8cbc288b9d0e83581e7aeedbda82b47285cfb97a3486607d5e085aa9" },
                { "szl", "7ced8c1eabb023fee9d73a5da21514641578227664371f707aa1fde28d06d3f20684df2d5225f0a0dc7b4f5a00ad730a03b154546fe3b52b4a70ddbad02e3c84" },
                { "ta", "5f4ea5adad72678374f3e058d2eae5dfbeeabf97b005db5476fbd181a30db4da89d5bc0f0ed798716804bf989c4b45889c1301b1e69445a51b899a9c54e96d3c" },
                { "te", "e0b9870483441c2a68601a662e6d748caa862136c7442501f7cd8b6f4a77c3191591b6ca03f5a4ffd0f74b1373c746309da1a9d1cc5de6333b4890876ba94c65" },
                { "th", "51cdf5b5be2cfab72f315454c9046e1f59573b1c3aa44a25c04f495a8907541695205393007a5e52ab8e882bb4a21893e0e3ce68c8ced6b8b04833cacea6f62b" },
                { "tl", "3e1d25b87a389ad38b382e0a4768697b2d67c45ac441c7ca95d764a2b2b6d30cf7807462ae4ee2d04518a9074b065769794fc1a9c12320e239b94b03c1e486f3" },
                { "tr", "5eb48693d21828d44585518fefa9fa9bfbd35b02dd3f436fbbe743d9a3a4ce08d91c1fe48a3dd5bbbdd911e7fdd70c9de415fbd6d5141de345fc77c7dbb962ef" },
                { "trs", "8b3c5f1c8c77ae05280f3417fb58d47a7cd49af2b46d7c675249e77d2e12c3cbb3a4772b6bc71a46a626202d89b53e248bbc82735be57a64e61abc70cbaae7d2" },
                { "uk", "bbb9d684660dd0b0e9c2441ab2d33c141c26edc8c710eb34c281434bf98b51375519b8b30dc4667982272511ed7114a99947f33907b07957a8a72e489a814576" },
                { "ur", "088a132c37eb0fdf9874d9fe060db0a8fa633f796098eecf9befc2943b75c7c07c7719975bd4a17dbb28e3bc06f1e229a6ae32515dd5c0f48c6d40509221f12d" },
                { "uz", "2b6512d0c7d4163f88534c27a2d790116d31faec87cc39a1069f568ebc334dd02039b3a3fc6faee3f963ddf58d39ac82179c07f9df053cf4e0b8717dbdc810eb" },
                { "vi", "c77edaebe11cc6f485eaef01af832ad947883256623eb925b6e7c6bbaee6b6f07a198dd65313ba29683559782cd040409d8f2869eb287c9dc50be5d940c2bbd5" },
                { "xh", "559190d209ca0ff15e12ac39cd0afbced7c9b2013b710f213d69b51e16095818b24f6ccf197f9808a3edc788e2a423b1429d722b82705bc9f17dda97df0d5efb" },
                { "zh-CN", "fac26cb7811d70414eb71a5795ffb8fc8b42530f281c0de8072510b6eabe8586fcd8c7ee429939756d8b4dd98533bec2034ee13b595964739703e7d6f1d1f93d" },
                { "zh-TW", "044e02a334369a7b84956494b5d37d9f7e29877921fbdb6e75b85e53d0a58e231a5f745ee1f9571b6659d9c363195050362f8ec4deed85cea4aa5b73022dc50c" }
            };
        }

        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/95.0b6/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "56e248de7c1343882e76d32cdd32f42a9b988b4ba1bc80c65746730553141687e55094c644305c4debf42cabe483025d2aee1c79824bff693e9c9c13af04e5a0" },
                { "af", "0e43d2e6113fff03da3b56ef3248ed791588aba3190f22d908723603e16ce7edbe615ad1f07993b1f15e8a68a416ec3030627f3ef772b7950819736e23d9d29d" },
                { "an", "48064caac86ad96931b954c63a94a1d87415a08e258c2c9b92395b05eca6d4e3fa0c77f94e1984383fd2092c96adf1d3ac9824a40bf1135bbcc38f95ebe50395" },
                { "ar", "c8c0f4f4d4a9bfa5dbfc3ec4511cf870163740975b8f28df6ae79282e6fa0e59d84db70e519614592a11aeb86a0de9ba66d87cf5c7b3d7293fcef642072437cc" },
                { "ast", "7db8a9ba786c845046e23803266615aba189d53e77dab3dad3e52987e4c6659f439c24af121aa751ffb9bb8c8716473f41be9d08eba0c9f101c7ab6fbafc9a2e" },
                { "az", "cc3d422b741a1facaeddd60030d3395c41a82d7fddfd9fad805ca094e973fc09a750117924f29fc249cd57c89d0674307f597f02010351c9252db6437db75341" },
                { "be", "56117382e3b937b42c37c5f17bffb0505a36e891f5a3514baa6c4f03ba0c4893d56024e6b5c75c456bf5c2cf69f6f8481239297ee485e2d6ea9ba657f8762ffc" },
                { "bg", "2239da1af5619a5987d2c095fa26cd357b6abe8e8ebe4b4ed59b571aa2439bedf50a41fba5e7208efceb5a6a37cf4d9f7b9482f21c9e647364ad33a43098324b" },
                { "bn", "120e1476bce358766c2b2c665348143ddc2f218ff00ee6079cd43fb08a5a17018881ff99bed804bd9f20c21313b0ccaafd2daba6b4f6876fa980bd51f0c9a11a" },
                { "br", "09cecf344f7b0d0308e2380a3414e2ae451968280cc3dbf00438d01f12752d5354da7b67342e9f1febc37d7927134a27e66370922f7fa20bb7aaebdcd35510e7" },
                { "bs", "49fe70508fd70a372144616b0b1935082c55cc74e18791337e45ddaa2b182253c20e3da18ec8d382ed8178c7e7396d6713bc08b3d75bad1c5610c2f543b0af5b" },
                { "ca", "cd93b0c9896c98257d8542726c82f7a68db7dc8013bae220d2e60a4a9eab1525b44150f72380b8c59af9cea652f789b41e95ddd5a27baf47c0af3cd2569fc0f0" },
                { "cak", "220b8a9d1d5f8768ca3e55b4be9bd0dc9c4970f143fb38af4b7065946f0b97b943b7e2c9054f3e0d35c71fa07826eb72dc30b04827d8bf87dbe18d2b44571ba6" },
                { "cs", "8c43f77df8b659d5c4c79fc6ca225d173d1d70914e665116ccf43393113b04387028db1d3d5989300ce511194bd3f25da19bb27e5bcf6cc75ae7031e1af329fa" },
                { "cy", "4820c35b42c0bd8724b5c798e1b9c40ff7115e6e22115915d726fb1b0c40b77194fb87fd44a14bf72c49ef4b5750bfc37d85b5b446a20cd3223e097546175233" },
                { "da", "892eb69abd8c4012ece10ef36082b0ea01c6d89033e430b22a7b6e5b6188d79e8914b02a9d5fdababaccb57febe8ef107175a0b25b9e2eac1abd03f69094ed57" },
                { "de", "59bc6866d06426e4b3b6d3a05971715d2f09205d6fc79073ef4db6cc884e054406a40c9461b75d85a589915e256360bfb7d393705d273cf4b0944577b3237d2d" },
                { "dsb", "7407a9abc8d3a5c018cbec8566671aefc5bca84e079a659836d08e344eaf96b2876fa477f550a7fb9036def5b4632281a22bc7cb14cef48b278d85c3b044c0fe" },
                { "el", "6524302474f135097c13441837da3ad609e65291ce2cb5e769a314302eee62b25222e1740be900d0e6f1190e3930e59ebea37136a2b1e3942990ba21ebcc5370" },
                { "en-CA", "fd5689a7d51310be675547c501f46bf320b4094ef409ec366178c6956fba022b478c23ea233dcec937b091c94e80383e9e6abbfa4637b3120183dfd035c0e887" },
                { "en-GB", "1efaa7f7fd6a9fd57b3b96f5ded62cde8e43e18391f13ed085b67f615c78cbaca6dc541780c3b346870988064129acb4fcfbf8702ecf01ad726966e23aabf53c" },
                { "en-US", "f5a96a61c87ad4fa6d03f2ec8d8a3bb516e2d2f795c3e797243bf2f802a24fa34e824242fbc891e7c74746dc328ab6f1cf85a695bb2f6b9c6c634eea7d80bed0" },
                { "eo", "fe89846aa06ccd5fe83d11ddc56510ed394c42711177f621aa32684f64746eedec7a0ef76c7b3f2b7ac33b98d861de605f8f9295b11878ae108320a7c1ae7451" },
                { "es-AR", "49e7fcbfd2f0eae25a00c2e97e256a13d088ebde8066e499df2192d9819c25106fed7bc59844d743bcf30b7395d9645ca9abc149992ce069f97ed4ec5f780161" },
                { "es-CL", "e36651866596136c15885708b7919133eb4651d600ec9a365f5fd0e15470a6a7e5b285ca6379ec94f3623be4ca649b87c6fa77dd8b1a7c2a3278720ffc1d13f5" },
                { "es-ES", "ede0c25bc1604efdc872e8331cf9e3bba4175ca4462bda4875a69f93c7621b16a898eebadbc415cece283da7d71c9bf82de758febce828eb88bd5d0a88649b15" },
                { "es-MX", "015909fa2e29bd3a637a0dee68e31e8dbc5291c058884116902979438c800f356d0b3eee08d175ed5db500c1a3bd37df2c66b385e9c50db4ec194e5b410dea9f" },
                { "et", "80c18700741e092417074c908f9cdef478165fad0f12a34960f4c2593d566f5b82cfcb5c3377aca9bd90987d148012766c90451282ee04694469e0774c632adf" },
                { "eu", "a91ccc32561c4fb8db23eebad5dc149173dee55bebf299e6c0ea5ed968c50170af47ed8deed80d6ba3bd5c0f0195a8947aecda403daa02f2f254a40b65365072" },
                { "fa", "cd0078737c1a77e3ccb528ee9b2bd0d301fec1de0a9637a0041bdc1b52ba8fc7f149a4c610d8ca67fc5149a9fbaf51ee3ba0a85f29e1f05f756c66dd639a5fc8" },
                { "ff", "6331e4b6c48de26bf6701b48450bc04e92e497725b0fac09abee9dc7f14de35e9f130c03546b958f034c721bfb6158625a79a5074b825073ea4af2655b0f4a80" },
                { "fi", "553f7e173d740169ab63e15cb86bcc9062fc32342998ec7584d228c4ce8cd98ce0cd5db5020cbd714136b3a184eacd7854661685955325c981b513bd0ea647ac" },
                { "fr", "9a1f60c92b918ea8507214fc466f5bcf652cbf872edfffbc9d85437548c417cb5f9ab1976e50fec536017751c9046e5218be82ccd528847387192954c69a9123" },
                { "fy-NL", "ab69287a816398e466cb07340a7c3c7f61a949b3acec99fd8f294894c3169923cdc7f49187b138519a66d12f7131e3d768395fc070dc09a4dfe72b674dec0a71" },
                { "ga-IE", "23a99b7abb2ac706f14466c555efebc8f2141aafa07fa15febe96671cb910b0f88a876666e8a7d89b5738d8c02a6ce8fb6661c7c8c9bb5bf0f3863b206957bb7" },
                { "gd", "d2950cd8e9cd6c0e51b93094702c1af6264db2abf1e0e8561dac995d684e8a9431850100e2bf9553cabeecb84c63e8c9f557b8a84fa7f69d709472b230a2c81d" },
                { "gl", "a815775ed2f8348d46d9ca10801e5ea578d9b20bdd4378a7f3e871574d41d10dabf4af3554bc17b67388ca963ed523491ac80a44e1a84b047c067b705e524958" },
                { "gn", "1c9678d079c1c9a7c6e5382388e8b719114c10db3b6fc8360a53f4e1b2a2c605857f7ed11e01a2469b1539623c455c2335019579acf8543d71b1ffd9d60cdc4d" },
                { "gu-IN", "26e9e9f51b7e5f8beb113eebe46003fa5b05771e3ecef041d925c28f2540a5e7ce3d53027a7428d8d4229c76be033440acda0c15859cf451917f3c272b2ef014" },
                { "he", "1f0c39d551291ede37d0d1a78b0d91edb269b7ee7f517c9972ddc1d0d3271e0a08916ccc3b0ac7effd57611b5b652f48beafcfd236bd9d70c50f43fd94bada4a" },
                { "hi-IN", "33be444272d3a6490d1d3a2bd34dd9cd3e68d3bb556d7f746e135b9db6f214bf0710d873148a55740bb8acbfc8f5070f3ade7dadc7f8b0f723a9e1d8a0abe4ef" },
                { "hr", "ff6227e2129ec157182def4da45d0ea0db7c61a81b860b51ff950b8c848a084ef084b11acaaef0bd11819941cebd01e4c41da90498e96dcdc1a6025d60e66ee2" },
                { "hsb", "872eb6d8e782856b1b59c9af21f6da051f757626a03972085497d1c50b95b707e8306274b5d78762adbaa843bde3ff64d8b48c144b09ebc56470f4bafef41cca" },
                { "hu", "db8f8f2b43a61b77502a5fef8bbdff16f1f95fb984975b109e29db1c88c0d5a4d9184192a6c7801fb28ecbc02231f61cedbc48a606c6031ef8c54dd7af7288e3" },
                { "hy-AM", "ea274e38110aa32181583af052801e361953dec67661e81fd58f492e28220b618b40a9eb67c9b677a5f136d4ade5e5a8cf360bd344dd1216252cf6841eff5dd6" },
                { "ia", "09a61bd0238849c7fe49639e93ddc1ef29bc049569a56c9311dbe185c547d55f3b22e0b8ae54f02aea6f08fc09f17bbb6c5a8d305951691811ad7e47f5c722ab" },
                { "id", "456ced970ccccca6d751e4f8d559a72cf43f1d6c77d17a4349335ec1eafb79bfa0a07351b7e0d780ef17cf641147d4dc288047c89a2b18d9ebbdd94be9a331db" },
                { "is", "d36b052667888e11d11eaf5e7e3a14847cbf0846b63f93f378797d5165ad76eb4bdf9144b279d6452b3ad631cc7b1f959711157f60c6c5380aeed326e542f0f6" },
                { "it", "810759a245b6f38eff9f727ab2762188972cdd621763ea76add8e70aac28f455c12eec96b88f39f0fe0e31de7271bb3106d954464e97f3758fa22d49d2637e1f" },
                { "ja", "d7d8daad862603466b1c03099e991b37d7cc9ee2f5a2df3cda5d180ca00bfa84ad335c1bd6de4fb692d352f6f2023cf5f4ea302c09e4fecd63e7a54c664dd957" },
                { "ka", "6db7df7a7839411d164a5fbd1fc470df89504aa5847c1e7275fdea52fbb574c78a6ccf749fdb74307525f26e4f5ea93b152d0e9fbd16a3d8490ad23a6feeeded" },
                { "kab", "16781fb4fd2584c415f5c0e3689e5717abdf068e347f5a4e8e06da51b514529faa1ed3a7af01aff5f01f80265808a1cc69728d0855a6339318d9d17edb03a19b" },
                { "kk", "25cf1d909697f9e24947eb7b605f7c83d624d82cf5e2be7881bbc5fb735c804ffd0b29deed3bd03a00d1011c0813a8182b3f99ed84ee8bef4fa9aba43c155560" },
                { "km", "7db60e42a29f6e956fcb1f60a9fe3c4e6826f420fffaddcc096a096fba5dd2bdc5969bc047912cdc59e0ad4d3482c0acaf07f92bdc84bece94b1b419bfca5da9" },
                { "kn", "521c292e67c35f1a987551436262457ab4819f1cbd2a231d5ecae15b1d6091db53b8340e89d95f0c36fc4e9f72296f198c9e82a92e1966491216646b61688e8f" },
                { "ko", "77d810b052c438a929ae56aa4403d22eafaf4ac938226ee656705245e4d94573991403541a11a1fc00fe16dcabac80d91381b141cfb4152ce0a8c8506906eecc" },
                { "lij", "40febda3a6781c7fe0e611cf3da2b2416b94f73a991450b269688ed049635bfa9f44b9d71c2e2e4f6a788a6900a7eec863aa642b4e84087ea29da2c01bb659ec" },
                { "lt", "946461cb535791671b6e3fd59e4c584623bbdffb8ec168b36ae5e9de0aca994b3d2a997ed118a6a951762f32c8bbae89fedf42812a60bc5f33fecfa211ba6415" },
                { "lv", "a2da9486919cf95e2259a595197bc92de09db923f003b14d0cac445a443e19d61a25601a1ac232b29c5c7afb9e74363bfabfc8b8bf4bed5922c2263e2e833dfb" },
                { "mk", "2d09e3dc1e5f7a71e14a1a20dbf46178823247dae5af94cfdd774ca9ae155da4dfce1d9f6af97a00334f02f4c91197ba5d0819e2a4ba18fa63a0c9d65a6e06c6" },
                { "mr", "9e23d2ab5fa54675a86f3283781beb7cbe729efdf0117108c3cfa92ef7357b97794a38215bf4d36f1496fea226764db19c147a1ddd82349a2051f21aea1fa7dc" },
                { "ms", "03b965bc0ca73e7b3647f9a19ffeb3dfe457ec468153301f5612e60f8a1111e312d90e89bfa9b581bf8a4ab39fe3483932eb4b1c6c4e3ba388060f36a39ec787" },
                { "my", "6692c29a6121f1c9b9ef892567b953a1e70f01c9c3839f9f7f034e83986b1eeda4b2df1a8af18dc12199f60e20200f85f33880d99d100bbad1db6b2a5d3969bf" },
                { "nb-NO", "7aae793d074d0d930ca16ed3da454790bb84583762fa68cf536494e15871f210bbb349bd912916eb596b606e6be6d6c8e5705ba081ad4fe70a85ccb9d68ad922" },
                { "ne-NP", "b6c20bf1ac9fb0d536f73c5b3cf6220c8e914b5275d694b518e43021733a8c8bb9f572a94fd4c354f0f7b3f89494705f0157d697000d21333914a1b0a4df822f" },
                { "nl", "4a603f1cb2d18a834961e84f44263068b04d78de0f52608ae1563ffb85fe6dd54a24c6297741c0a0b85ba7b60326519a757a4290fea159a57dbd76fd9c37c76a" },
                { "nn-NO", "a076cf4540b68891b1a77210da711c4523f21e0acd4521f2d7f5ecd86b00b4b478322defb69630b3ed9af529a222a7a779573d72e191925004722e2f562fd805" },
                { "oc", "f1462df896c5ff98c9c25bf5dfc3fcc606eb4958fd55191ddb7bdc75e918c66f62f8e3b760797e30eacd5d548792efd488db07fd3c3f9495c0db65bfdc30a9b9" },
                { "pa-IN", "1bfa8b68781ffa32437650b7145aed1cba71a15fa57dcdd096b413ebabbd004f8a5f457e91b8bd93607550934f9fe2a3727cf43ed645bc516692610b749810b3" },
                { "pl", "7aa5cf0a1f614310b9076a2784d34a625420bb7c5d8e3e7b679ec16a79cbe3f61bccda740a5998a9492b5de9ff7d62483329104f2caa833e4955e2dff4ce906d" },
                { "pt-BR", "0112ac9a44d74c72fc80be5d19625c4e1b0ae4d3f5ec575af2874fae94e29903d267621051a20b6898e09212eb5aea9011a6caaf1c585dcac0783f93e1827c4a" },
                { "pt-PT", "0d5c4cf19c1df35095df52af4c547540a5471b7ba0a04cb89f0b49e5e533580f0823d406e5549fad1c066dcebb0a6f478bacb5d66abf0653f1f43e6c9cf494e1" },
                { "rm", "94140edfe0b89f49ffca957bf6596ee3360ff71bc6a0943a46969fb12627aea23abf5886c5271f2e05d43361ce3fa8888a65e7717833731b72c675dfc3447c32" },
                { "ro", "dd1724ef711eef49025afb758becb1da758b5b5e05699506bf324a4ffdd01b86b87356807cc99fa635bfc4eafff054616299bdbe2d84819ba8a87a6a720beb7b" },
                { "ru", "67fe8a2d521a13dce55f15e89eac223d3e5f0400bab387f2e63a95006a4850c5e0961fc1d441bfa78e97b81d5eefe3fc901eadb41cc19370b7691e6de3e1d0c6" },
                { "sco", "8044f7b58131f98042881d9ccc7305bafdbf819ce4aed9bf9bb38e0048637e3c9ac9e523bad74b4588aa04025003db7a15527d44c78b0a8ba224738ba8c843fb" },
                { "si", "8b40a36418d1453223c84fdb2100d37317107025e16db3b1cd6fd79c32c90cdfafb8edd09dbe2545c6e54b0c8d5b08239b0449819e8df4299c7ada18cb24b6eb" },
                { "sk", "914759a47b4d29c580c2b5cf30573d60b88a59340dc12ec825a9b4797634be80cd6de15adf2123276372cae4eeb0a788b66fefb29467d26e20eaf48113045fe6" },
                { "sl", "8b5f7bf5c409aba7d5300afd5e2874888d4e88c62b618d6eab34561ac82dac4cb0c7fc7f396243acd9b870f56dd587b5e9b9ad8fb746bdacde9cfaf2c4a2dd69" },
                { "son", "fe61953b1bf8a231fed0058b47b35a3e23b7f56c4aaf4a9f34010e2daaaae21db5ce37c8a2a300aef793b1930eb5d55bc82c3540cafca87aa745b4e6e694694b" },
                { "sq", "e7c722e277aa8fee89a5f44235ec831c8cbeb6ac32e3ed824ca3a5032371a482334b492ab8ddf116f8197ee9028bdb883abd1ad86db8df51546d269964abccaf" },
                { "sr", "8fdf3b74cdc393b9fb2f081e079f8166b69aac7449fba888c336b24b44e8d47349dafcfd1152352a3596f146a3990d48dd713088180b5eb8392b50a4885a032c" },
                { "sv-SE", "a74dda8d45345f1b7cc30a16b0dfdc52bffd16ae57740e5b0271b4c9fb7876eeafbb7757740f66d7ce1f727f3a11f5ba1270aedf4a1baae52902484fc6be85ad" },
                { "szl", "451a1129a17fc33f30d0b93ebe386ceb324ed85e0696df53eccdafc6ecfdbe7ff5d4bd99e5c6d5e24ba3e6512ed1ec31887e44fa263d2b965b051d26cd5aedbf" },
                { "ta", "dc3d4df02e40b3d67125a7a2521f2ee6f31a0ee428bc6fe08bf49916127d7f1fdb54e6ccafa1645a34ccd98c29b426dbb3d16d0a88c90a9f684b24500aea646f" },
                { "te", "781ec46ba8c7382a864dbe7c7875cc5455ceb9bf4c537efcf959db9bed13b9951376f8b8890f0884598f5822477485691b4c3e13c5c288d7f776b320341fc661" },
                { "th", "a281559266fefc11befacc410a11c5cb5ca70527bd1d1672044fea1663f291785f557bab5b9623083d508dab2ce9d7e1383c89c872d1a0d96ba9b0ad2b71d992" },
                { "tl", "094cc9430da13369b04c00ea8438b8802e16938ba145202cf741275a5eb9c583a447a87697dc6ca6baa379970bb3d141e9755919667858c7dffc3624fadc9f1f" },
                { "tr", "3fed99ad2c7bbb5b7cfe4f5b220ad8123bdcfdc0fcbddc1f60a2920bd8e442d1d6a7c8c26c2a8aa1a0cf2bfa05f912d43b10584b561fbe0cd5d3ce19a620e5d8" },
                { "trs", "d61a755eb945f364119b00aa9999eab0ddb26efbd72494273f06029375de76267bb3937ced578979c9ba1f3ea5b33acb3c3f240c1dea1b559ac0d0cf71079e78" },
                { "uk", "2299098ac0718134b01e854b13f1d42eb44037130a5a3a97a0e795b131707b179ff5f55d9ee74eb8285e416fd0e1bc2b45a2084f8bebaaacc6f3746fe41bcd0f" },
                { "ur", "9cf0bb31811508db7eeb5a12306b16591fd9a1b230e109ea388f32ebe9a5e9fb975fa0602d664ceaa91c62c467cbaa4956eddd01d8846e2ce496aa29c75226fc" },
                { "uz", "46257a94feb5f0fbb59008987107399d83576c1ce553ecf4a693f0ef93c825de5d75acc75648f212aeb8154bc4f2077e5db3432fae26c9b4f5f99576148df939" },
                { "vi", "4ef433dbc7aad400a2fc85a739780c14fa4670b9d09aff7a9f3992246b214ca7fc01a8e01e51ccc766d04174febc225381e08f29d3e9c999d11ec96d0a58d125" },
                { "xh", "cc4a62df677a4b1d9787c83515b9d8a7458e28e7b3d620396c9cfa9a18866a9686ab892e47b88162bd3d9ecd4315479d542b8ebbe4a7a155e6183410e7c8d4af" },
                { "zh-CN", "5257bf3de2696031362861482565e8795921b7881e3f46fe00bf9d9b2bccda2064ec1d24f80f779d3bc45385ca0296f9b4d46afb3ef4edecabaf2af225f0f1bf" },
                { "zh-TW", "a1973bc335e96db4671fc9dd78a86df53a5a201d60f77938de6846e6b7c210039d8dcc016834bd959b890242dd801840592cdde4e4283289086c472fd193459f" }
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
                // 32 bit installer
                new InstallInfoExe(
                    // URL is formed like "https://ftp.mozilla.org/pub/devedition/releases/60.0b9/win32/en-GB/Firefox%20Setup%2060.0b9.exe".
                    "https://ftp.mozilla.org/pub/devedition/releases/" + currentVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + currentVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
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
        public string determineNewestVersion()
        {
            string url = "https://ftp.mozilla.org/pub/devedition/releases/";

            string htmlContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    htmlContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Error while looking for newer Firefox Developer Edition version: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using

            // HTML source contains something like "<a href="/pub/devedition/releases/54.0b11/">54.0b11/</a>"
            // for every version. We just collect them all and look for the newest version.
            List<QuartetAurora> versions = new List<QuartetAurora>();
            Regex regEx = new Regex("<a href=\"/pub/devedition/releases/([0-9]+\\.[0-9]+[a-z][0-9]+)/\">([0-9]+\\.[0-9]+[a-z][0-9]+)/</a>");
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
        /// <returns>Returns a string array containing the checksums for 32 bit and 64 bit (in that order), if successful.
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
            string sha512SumsContent = null;
            if (!string.IsNullOrWhiteSpace(checksumsText) && (newerVersion == currentVersion))
            {
                // Use text from earlier request.
                sha512SumsContent = checksumsText;
            }
            else
            {
                // Get file content from Mozilla server.
                string url = "https://ftp.mozilla.org/pub/devedition/releases/" + newerVersion + "/SHA512SUMS";
                using (var client = new WebClient())
                {
                    try
                    {
                        sha512SumsContent = client.DownloadString(url);
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
                    client.Dispose();
                } // using
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
                Regex reChecksum = new Regex("[0-9a-f]{128}  win" + bits + "/" + languageCode.Replace("-", "\\-")
                    + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
                Match matchChecksum = reChecksum.Match(sha512SumsContent);
                if (!matchChecksum.Success)
                    return null;
                // checksum is the first 128 characters of the match
                sums.Add(matchChecksum.Value.Substring(0, 128));
            } // foreach
            // return list as array
            return sums.ToArray();
        }


        /// <summary>
        /// Takes the plain text from the checksum file (if already present) and extracts checksums from that file into a dictionary.
        /// </summary>
        private void fillChecksumDictionaries()
        {
            if (!string.IsNullOrWhiteSpace(checksumsText))
            {
                if ((null == cs32) || (cs32.Count == 0))
                {
                    // look for lines with language code and version for 32 bit
                    Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs32 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum32Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs32.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }

                if ((null == cs64) || (cs64.Count == 0))
                {
                    // look for line with the correct language code and version for 64 bit
                    Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/[a-z]{2,3}(\\-[A-Z]+)?/Firefox Setup " + Regex.Escape(currentVersion) + "\\.exe");
                    cs64 = new SortedDictionary<string, string>();
                    MatchCollection matches = reChecksum64Bit.Matches(checksumsText);
                    for (int i = 0; i < matches.Count; i++)
                    {
                        string language = matches[i].Value.Substring(136).Replace("/Firefox Setup " + currentVersion + ".exe", "");
                        cs64.Add(language, matches[i].Value.Substring(0, 128));
                    }
                }
            }
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;


        /// <summary>
        /// static variable that contains the text from the checksums file
        /// </summary>
        private static string checksumsText = null;

        /// <summary>
        /// dictionary of known checksums for 32 bit versions (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs32 = null;

        /// <summary>
        /// dictionary of known checksums for 64 bit version (key: language code; value: checksum)
        /// </summary>
        private static SortedDictionary<string, string> cs64 = null;
    } // class
} // namespace
