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
        private const string knownVersion = "140.16.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.16.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "bda4cc96b490d944ffd9bfc2680b19fa7aeef3eb78f71f0d46b0788a9e70c63e12ff2b8b835edb505817dd33842d9a94c2bf28279658941a77caf9640236629d" },
                { "ar", "8e9c4e66dbf7da40592083312200c29d351bc9514d1b4a721c7279eadb36fba4e140bf86381506c47a995c7426a6d4374455c224fd4396a6405dc1219c1d4911" },
                { "ast", "498872eb7bb066d105ac6f8dacce30d514750d22597e8850a5b2dc527a852a668ff5466b363af32c9cae7af452abdad6c4c7495c9e7a4a42e3ee9a2cd04ad40f" },
                { "be", "15d749c469d3d9f5924650a36cb57f50c5adcdf9b000176f07c7e918774164560db5e09e611145cfc3da9904d0103d918f4a4ebfd94ed032fa6103ab5730b63d" },
                { "bg", "ddd7e3d9f2bf26fe3c298da33aad14688df3cc247bee7c3724da593b92fe65ce566fb94219525e692d504ad79717748a050e8a88e0d3f705ba620499f7c6a57f" },
                { "br", "3a068966db811625a9b9087c498b5a3b8cf739d8f613e9c5e166a1af18e38b2fdb34057b039dba7d1bead0de43e9482c57a99acfb576853fad3e82d07ef41a5e" },
                { "ca", "def0bffdef0963b5a952416bd1df017c21671e1a727f1a7508d407a2717b83e334853acee21509e36c32ccf71896595a8e68cbafd751ea655309633fb85283d2" },
                { "cak", "efd359651abfb3a7a9324230f510cdfc2ea9460881380057a756382ade8ae46692e06a297032e5bf7062fbf93adb4fa3d7fb6ad82ce7f0e75fd4fa0a68476d19" },
                { "cs", "62508cbc5a8ba09e83f8ffe8b0d311affcad81de45d6d9ab9b0b6e21726bac625e4f0d894b0f8cfe747837360dcad6e0d68cedb9f46188cae406452a98aae00f" },
                { "cy", "abd8cb1a8d73464f1a0b836eb31413d9f25dfb3de94855497832000bd2d4faaf8ac16fce189a061c72416b5aa96a3524564cdcfce76946cb71d9fc00b0dcb6b3" },
                { "da", "9199394c1dd3ee03227d04519c0ad4607cbf035886d14cdb8eee498bf4acea1f85b7ddd1688e2913c141eb2fedc7ab60f239f0ed971456163780686932802d50" },
                { "de", "fae99cf3cb8bdd0f72f5631aa29fc880ec4ed4f67817316c4500097cd156b9a9a5d1f8f7b6d6c2ed332b4ecaddf86ab209c5480e4b46d15f7ede11dfbe2ce48e" },
                { "dsb", "c7deac8a1a3bdfa82e33bedd0f09b0f3648e80c3e22899ab125daaf0a61d7d9c214eb437a0cd07873eea6d441aef11ec986d5842bac8d8b56ef5b3a39b074ad5" },
                { "el", "adf8631b21c87a56d43524031bf5178926f7fad72efd4054bf712078f1e0ee58b56940578f4386c5e71567384d4e5a3a1d9f3a3abccb13adb1c224ab168e0ec9" },
                { "en-CA", "f256a212bc9b1aae78eca8975cc5cbd6f35a2a0d7f0ea10f52cc1ada8d2d58f253e084e8f2752daf278bfa22d3e6ef7a4afec2fd156b2ee3915d8e3a4f796723" },
                { "en-GB", "32d1ce736f578492629f1720ef3bfe82ff2edc7a29471a4fa5883b965afe5ace10d6d37cef44b9cce3f4842eebe1d97a9a046219f9132ba24fa9a0b89ff3c1ee" },
                { "en-US", "add9604102592b39e4d0085a1405579e3c5dd993c5cd6760462cace118f296304bac82e9bbf687af9eb5ef14b8e75d41607249c45d58b937d6b466b51d31c6fc" },
                { "es-AR", "32d219cd61f4b2f5f0e6f13f0c9f5bf362a51e6e810b0b0e0fc00c3ef790dab6056887d7db7209488e6a91540fbedc2638bb90ce7b4f755800855ad6ffce5cc7" },
                { "es-ES", "ca3c86315a8761f71fe9129d49dc5ebbbbec864d76366bd9e8cad61323ac393d452da23d972be62c154d72dcee51716de08d75546a6e4c7f677c1806358d2369" },
                { "es-MX", "3071d7538f01f48d302f77f566904a3ccaba1ff711dd7ed9b39e30b8e3f9484d2585a6f37391136f62b1df199a2decd7eb9596db07c44bb83e3f79894ccd1283" },
                { "et", "0d0fd5e2937452f372065505bafaaf08740752dcc2cb4f279dcee3ad4550ab76d4739c622cf3410f005c5ae520f774ed02301c7693bb5944990a55b85bc52dde" },
                { "eu", "94b7c63cdba48ebdef59ba5bd2027ed95bdbad5a1990dfdce2384ae2c76aa72c41eb1840b448dfc868369d07970a5e42957d521c859f9303ee961407f8b6da52" },
                { "fi", "5a8b38b93d1f769b7c42418b5a7c5e7d754f842ff9e78f9a682b8fb2850ec2027140422e9dd03a6c1b514409ca7a9769803ba79b3b560c7f9c5fb90a85a694e4" },
                { "fr", "a028c233f97412fefddb825f461eee98da3ae3e292a4e824af84810635fa5e3f57f89a8bbd932019e17fc3190f36f176d01b5134489b47ef1af3ed16d23f07d9" },
                { "fy-NL", "0cfd09db822e020815e9254b06c6e8213cd36c437ef7fe0d9ab47e6a7fce85ad02dc4e7727effc8c340dcb65c9bc50d6ee830f59c369e6d53ff75038592187f6" },
                { "ga-IE", "381a6d9202db47875d0ebb634d4e1029e97bbe94aa57c6d1a63638db6f7d67b6aec09aa32e928c1ef3fc3bd20bb8724dff8e4b27b1e37ac34551e22723ee6b53" },
                { "gd", "76f344fa87a949cff0f840589cc110ff2cb9b61e1e8c473776643039ba0f02fff6d9c954087d753f0260ab79b3cba92e4c88975e4ba8c0a4146c2738d66885ed" },
                { "gl", "456194178a56d243dfa5bc0fb2c180373eca3d148acf1be4ab3801657dd6d02c9d853da555efe399f215b1d62665596ae0c2381369e8f722f41560275cdc9aba" },
                { "he", "ad2debad0f590ff7dbc940583724a39bfbf7ddc4298dda2c2ca2c0d28884d9bad5d590840cdde7e39f93e4fefc9acce0284c287eadec940fceed41fdfb5e144a" },
                { "hr", "d01f9b5eca7b1e68a0d86cbfb3684861d8e653a4ffff02d35a3b9cdc458f8d3ab4b2240117385de3c1f0e7bf3f1aa8bcf1cdf703a789bcf833e8d62fcf3dc6a7" },
                { "hsb", "eb0971616173321a84c0dd02d8574f625ab161cc5e72a7232560c8337b3ae0e2f3d48f76343c3ec6c328cd4b600fc8d693b535370b997a8f3767cc83194bde77" },
                { "hu", "1878c320b49a560eabd8909f57d9f2404b222e2828173b369bf749fd843b332990eeff6e2bc8535069b464b23872a144cfd918bc39485e897148df3afabe1411" },
                { "hy-AM", "fe640a8aea1602652d7acd0e096ce54010b9e52847895b339e3897fb0d105d7329bc0b27f565fd6944a7eb1de072c25f83a4681c35072342d3ad027bc10f7b24" },
                { "id", "19e0328b8619dbb385b61aef5c8b9bdd9171991340aa79964e2b3d7af0b68932d22f33811ea060688297a873bdec09edd4fff6456b455b302c1c28ab43861615" },
                { "is", "ce70265bff0d194df3f8d69260108cc28883ddb9315ec315483b716788101d36dca6a3a24ee6d9f3f3a2ffed5efbda8eb898ae18f64608f995c8b51130ccd31c" },
                { "it", "34337f7a36363aed6fb1500ef09925014ec5f41163ea7a90d6ee9bd546180b63799e1ed9deb2adddf50f455e2e0e70871a2c7f5dd6cd7ce083e29143caf11914" },
                { "ja", "e565be50eb32e553f256d7d6472a843a9a24c05c6ace98b64040159368ebd23b205f0eeaf90764e18c9b16dd2164a1ba908f2e3d6072adb477b4f99dec5716ef" },
                { "ka", "f869998a3f80c2d32c9027e9b6da85a467736dc73fb5add4e3e9df6f348bb51654f80e34a4ba44e51ae5067ef1a9f6c7679835fa1da1459de420901fde79caba" },
                { "kab", "32fa807313fdde7485090b29b52a82383f0b205cc54ac8b6a0ad3bb5157600a735898d5c0ff8563868f8df72fd9ea15876f4fc96033ad6b3197d4fe6b61eab29" },
                { "kk", "cf03e583d02cd8371bb256ae660625e4cffaacf26c440a7925f98365cdc31b8f1a2c9c115c28d228e46d2626dedfa856da42dc66a9a5f0b70a7cf99f7a86e748" },
                { "ko", "3e852ed05d8a39a4275e7775d63ed712c6985d5bf7da8e5345c808abff760ed77ba777e3b8cd0caa6468b36a5ae40fa78b8a50adb0edf7823379f3e4ef5387eb" },
                { "lt", "fce6d37da8ff2e40cbf746db1d9657e7f017aecab93587fd314762f6f9195fb87135974409f8566465177d0281e1ceee20a1c21950404ff2a377c0e2e2fee5cc" },
                { "lv", "9c1a68c01f6788e144ff7dd9f63d424d7c8463dcb40c9ee11a73b8aeb5f23f9661c6216454bd1d0539550ad1f3a883063a16a134cdde0513b215c01b5c90e2f0" },
                { "ms", "93260e22b65380f88ad0ebc98b26a5f2e87eb677a37af38d19fc182cb0995d8d1fd8c6acee86578b2dc757e9f5a5507188185d2bad6455d208a099f963be2748" },
                { "nb-NO", "555ce9a42fa3fb6efd44e6fa571836f39c17afe64163c8411f7471224c4161804230f367e8824bdaa36a6ef0e9095705d4e648fcc2d2f05ace565481b55dedf5" },
                { "nl", "624963289fc5327c1d8a612f3908ec9664595d80aedaad935883fd3e5a9d7c31708ae6b807e75cc0c67cd74acfca14bca88b10830484a5617ed425b3e4b92750" },
                { "nn-NO", "a21a4d32beff36cecf5d23b02562a00e780237430063a99a66d562b30af72c95ecaa86416acadc0a199d5e9dd370e6769e87c76eb9c306df754f53bee62d8ba9" },
                { "pa-IN", "3c519e0f7437611ffb1b0b7dad4f8cb21dfdc56676cfae28451f9aa3ffad3ff62a9d2d641414a0eaa2554a78d385430d5c7ce0e9faa47081e33fd22b7917a003" },
                { "pl", "753d1790a56ffa88745b66b2027d51098101007baf5c26dae6b182acb711a682fa6c3cdc0859dfb2e4a25015d307c5cbe4fca4183aea8684f57beff5b0611a68" },
                { "pt-BR", "09b57da0c7949a976bb17639712de9107c9d8f7db9c245679772ef989d6b94c37f988fea7f484b78ae67da7ae1927bfe505af85eb34926d5b7b45e6ce03db601" },
                { "pt-PT", "d95c4def898f743c135aee60c9a4c3c0d80d403f36845306a1a30643708a09263708de7247b4ffd171f31fe2f2d9d1d271ecf3015d6b9ab2aa90b67bb1ca1b32" },
                { "rm", "cc7134715614799dad49a6c8ab61759608cd7fed6019b4ad5a4785f14d879e95d412b01ac1cc2cfeada9b3db929d29778341af7baa742ff364fe742cf422cca0" },
                { "ro", "f50ede563ed39fd9ebf32012e315f25435096bda33f934b1d384c7575901eb5bb0455ef3e1b0c9bbb0057c0034ae74e0cc13d71859877cda20db5651ac1565dc" },
                { "ru", "c1c22192085e248a88d19628e916f3b1c28502f87eec3dc571f927fcd71049a364ff369a30d4b67140ac8fa8a50dbd6eef4db46fa21514ec8089a9c14a1119d0" },
                { "sk", "49e422f3219b68797fca7c4a3bf305b455c696dfc7e0f9956ac298d2617555bf9ecdd761ca8830c81005a3739f1e37e08864c82fecd91b58e4a881aad80e3331" },
                { "sl", "dc8a8cd48f420019633875006e436ecc7ef257a41743a11a6d08160516e6e8d654015ace3da04bb51b6f7731fd221d8ecd78f1bef9d1e1eedd23130732a84b15" },
                { "sq", "3e60e230aa419c2995950e87240cd0aef1019e90f02681085d255f52a10667961bd75409ec9214150031145489f00077365e2da4ed6e79e72b06c9d3d75c9504" },
                { "sr", "437e47e5adb6cebf67064e52db14490b9ef7927132df563a0c593853da56c3318d60b0d60be29514dc00f1bc639c67df530579e2e62fe9d350dd3a366ac2275b" },
                { "sv-SE", "2168892c54b8462ff09e19463ab75d177fb8f517d7a33170c052a0a6beea8f38a639b2f29a2e9f93b56db2c09ca07cecae0ce9476c50ac259ed69397bb360a13" },
                { "th", "4a11e2e21934b5f675c637925cb4ea8ca4934679d69224298250ea56ade9351ebd877fe7de166d5181d9426eb54950c9c84ddb0a85f4fd6f2fc79fd5bf4261ab" },
                { "tr", "d59a5a9b4232e615f366c7bf92f69106addec84c26bad549c8314cac0d3e7c1acf1529822039eb340a4aa69166d50a845ae6063ae31ce02fd91122266a0ad413" },
                { "uk", "b0a0c7ca26e4160850627e3a4e4964377e9570d76de0db1a5993a30452e252e8a19a9531e44b2d0a4c826ca43d6455cbef64f1ae43e6576ae14ef9a95eb95468" },
                { "uz", "da2e230e07277e0ce55887de177d58cc12fe5cc8a477b52dd5c10dd41372a8d6600bacd70ed66408f80fba96a310b35babeaad0d6093f0c24b2938f68016e49c" },
                { "vi", "d241e476fbfcb56980d181a3f9814c4bbc97f7e0de42beeaba83528c13159f0e22bff5cceae8822caf85e99e8c2f9ab4ed33b54b4f936bd9cfdf7bf4e7dd1418" },
                { "zh-CN", "c6c7b0cd752f09a6a688c9a30e7236e536bfe3741ce25cedcbb3f394862be97bf3c251826f135ff4fc14bf1ce47a83cb1099fc67536862d28218ec1b09ece504" },
                { "zh-TW", "86f3dc7e14d5a97f12292f9e2b7ff898d011ea1cc8833b8e57d38695790e58a6f61b8e2706a72293d6f926a4bbf2eacb48fbecac386dd129012ca51cf259762f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.16.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "fd9c41395d22b77db8292b7aa62bf864c62082e726099887dd305d3ef1140434bcad0042d1086a1c2f2ee789bba7b792dde270e5e5d516be4e516d742e06d298" },
                { "ar", "ff669e885b989816ec2a6a22d95471160cbd38c6cc3d5fc5a86ebf6bed806ea7b373039a45a18214ba10a92782970ff42b73aa62112ec565a0550a4a44b94904" },
                { "ast", "2dbc80a96a4f246c4b7bbdff50e0cf5fa3b26ec07bf5f2f78f7e1fa705304d075d551a95eddb930b1eaf1e26f42454a1dd1a3a3f69a71cd43d74fe2f408b6fed" },
                { "be", "61eb21f5a04fec6c5a0e1ba5b90635c3dac8c30a9ceec08767e80231027ce0e6fced134f0387b5fd78251e22e1a51712c30c24a8cd0c7361828881a29d8641fe" },
                { "bg", "dae769bed46c7c9e942095a7154d1f7f17d05b6dc3f6986859f5f4d4f3b83263f82c3f437f8206ee514912dca171522a45bdb9de42e065b4f4ec25fc859e7a4b" },
                { "br", "8967438cd82ded0ea793aabed3b5545d99f949f1e6db19255a4373c209c4f6877aeba05b026f8c667eeb1eafc0e532e317265f1c678ccc5367f6d847eca59187" },
                { "ca", "785d9c3b84936e572fe80a187ffd2c5ffee8a62a3b75941ba8ea71b4bbdb6f4b7c725e662c32e0d743e98b09ed3ab55ab6bb620ce72b4411004ab89825847ddb" },
                { "cak", "6f397843e153f2ed7b7e1931e86f9e8023b7e1a83ffcfcada7438ed3ba8201326161fa6c6d767f37a2887b0e3d7a07f2925c1fa4dbf4bb179c0364d1a7a128be" },
                { "cs", "fce60e0b25464498d39e7fa6c8c5548be46ebcc853e52a4c450b95fe13577fe06892c20e95946608f26ca368e4ed8d444a03c1c9e735c0df7e8c2498b8ce29aa" },
                { "cy", "699e03208c7853aca6e47fb85a7db2a6075a0b4dca5d75b70ba4e4c7b5af0b769790c4ea1c7ab6923ca6300299064c753b9536983050cb339952be82be9354d7" },
                { "da", "9d8c098306e102a0debdf376bcd3386242fd1e304a2af7f45e68c6fc6c5519319f1d08f2a0a80f89ae4efa28fa447e12ab19916cf2b52c2802f94fc8399dacc7" },
                { "de", "a99a99286f2f6204b1af3574858231835b3d13a31e0620d198aa42d7b8a4c156b43259cdf344b68c1864e3e5daa34d2217333b1cb4016c017aeefa4942b19082" },
                { "dsb", "86460c2bac55d2b64df8437b65bde02f663d20cd79f9b6f444aa79f4fa6476133bc79ebb993546c13172cbe9ec23e4aa2fe26655d3454b883bde80a0d7af971f" },
                { "el", "82ea911b622201ae836910c8eddb9b19fc2e7432f14f6dd101c02cdf7f7d49252d8595e363e8e487301e2eb80c777e16cbc5fd4cf249852dfe2205df50226420" },
                { "en-CA", "770432a491efa827ff7c3a59a39c619f17375dc28b838ee002b54442f996d710560aa055be83d287efc3d0491a65b23020a4142eecd652bb7176bca473855da2" },
                { "en-GB", "7058d1c7b8553a7c3f47a6f5d359ab237174af297fcec05b9f8fa6ccc8226caa8bfdbdaf7f5e2de4a0109b01b838d946226d5bd23d5d0bba1680f15e26f00cc8" },
                { "en-US", "288f863014709e4531fbf0c6cc98c73cea82e16dd14483c00ccb33151d0b744103564ff2bbecb5e1973f1ecec0a0b95195159fdfadb01bbc42e4d61b51fd263a" },
                { "es-AR", "5ad29a6bb1582e7ff56108e02c78c37a810e08a3b52cd60c21ec82cea6183e9d4a647f372aaf6897eeaf9961968a56a48b0a525947b6092381673620775c85c7" },
                { "es-ES", "5da7c7a1d246167c6314f47c7b9cc42ff129805e20558c9ed9928fb6e5c276396b478989ef76f8648f68c42e5518a0e067802daf4c5805c1e7a4f9beba587d5f" },
                { "es-MX", "93d0faa7ed1f1eea5411e903a54a4461ca5b974e6086c25d34aef749bb1cda68712ccd407eedfc3a4caddc0b0b52096221004a043ee44169bfc181dddd5eb443" },
                { "et", "a74b5f7c517a5d37b394e98d89f4f32064c636de86c8fb91a8290fd7643335d0c144649d4f782cd2067c1563b52eb80fd0e0169e17c18781f17aabf3f43c3136" },
                { "eu", "bf58692cd8beb11f03979c77c2ef819949d35c5dd4ce4dfc2362530d5d1305a1f058d9467ae3855b2af817f8eed9d14ec523232842bbf0ed7d2d7adbe4461d88" },
                { "fi", "26ac92a3a50c13b6d587259510e260e75e4020eb8d7a28cb9a2972497a270ee0d90ec71681d022bad2c7309187d8d0dc6610ba220c369d43efaef163b7704cab" },
                { "fr", "1c161908a30c54cba43b56bb8981b28647882438352dd71b7e829fa2225c3570ba968f38e0c34d7600dd512cac032a36cf2c0d22041c847a134517757636f2b0" },
                { "fy-NL", "b69a29f51046c2247ad9945f4ef3dc6f765b5c825f1f04c8b5855df3be4f6c3dd344731ade7a3a539c45f8664d4a07eabb29af62fc4d1144b82c97a7e0149f14" },
                { "ga-IE", "e390dbc7696b7f9b4f1fa6f36effacb022fda6c473aa3dc5c65dee27f564974dbd1a4f6eb1199d5d8fa34ddb8ad68d1c295fd22efbf312112dcad09cc6e1b1cb" },
                { "gd", "d73735a1acac74405f8601896758148f82b3336cafff9595325f144e358ec402cbbd37522cc05da74f9632a60a2d2a80c3646d7238e64eb394a04c0de810c6ca" },
                { "gl", "a063082e83256e272c5232bfb328f051ccb023b3f20b0910f422aba30a96ed1aa592923148fc413ae792317fef861768bf0c74d75d743b3dddecc239cb5e4d55" },
                { "he", "13ad96d0043d85b5039b436c5b449dff95a8d29b64bf0d1d8e9f3102e4eed8a4e774573a698ea0298669652cc40e19ed1ac1e00f5af63cd33e408a064e8bcff4" },
                { "hr", "672bb0c34dec352b4222059bafabcff87085e9c9d88d070143036933c0784829fbe0b877f394d3e8633b3693526f4d05196933245ee2a28aad033d0da4996e18" },
                { "hsb", "28b2e41fdaa14a0ec4618527958a17b92afb647bc489392de1ca6fb882163ed5abceda4f017c674bedbfb6cce6f90cd7c4ef0caadd891f065239919913362d5a" },
                { "hu", "8aab69a5a255e76cde96afb7318b6c48ec1090ca6253e89d0003bb4b05c086c17073f1cc0b5b9956644f26f7d477f69064f57b961ca07de9ce237204409a7c5d" },
                { "hy-AM", "112d0c08df7f501a3418223b080918d2e81366c705062ff3a427f6482b5cc0932921a64d697d5a18fdd83ec17ffd2c897472398e1ede09345d8a571a16e921ae" },
                { "id", "7760e05c950c324c1d0469b2f492256e7f3894424141c0ea0f6bcc6be4d1e1ec37378091e1a0e2ca2281975e0282b85b8eac4202be287489a9f33c0bbea58a49" },
                { "is", "4057765c3013876b6c48ec1954ff62a605389fa9838915eb220374c310b75b342f589e96013e253dada70295ba992a2c35230751864ddced1323338db4481139" },
                { "it", "580a4d308a9f4451a7787abe7d7450c327058a0ded01a49f6406d6605f870d5b425eadded35cd02441c41a0935ff8457c20184e54fd397eb8a907897302cdca7" },
                { "ja", "abd814a162107c5ffb224c28589066a2de9e5b616946965766f5ba7652b57bc3225a2bcd3684e6979fda9d1d44377b7b7f2e6d666c4c974deae35c8e8bd63d09" },
                { "ka", "933f7db4922a60a543c62bb469703eecf03e7aef616ce23f12799ecd88d3db5e8be0e26806c4ec2034b0872a067cde985e69631ceb83dcd57ce68e88e0cbac2b" },
                { "kab", "32a3c53f74619e7026429931fe65645f534a01fbeec2993035fa857a74db755214346ab53ba8af4c271d05307d3f1c6b2e7a8240d511db4d67096543ccecefc2" },
                { "kk", "8254dffd1375919a12cc2929ea3b013465b139f5342a69c0436426af7538e3bef8d147f9548c10762c5acb538742e1139e12be1e4e210b8f001c8e2a34b0166c" },
                { "ko", "667981f413e98bdbc8284b234dea1f64d977e26ff05894afae4eeb77e01904577c8947cc362da7e4bb3f93576ad6b06996e16f897886bd002850665b9a40950b" },
                { "lt", "6143053bd13130acbb002722209843cc0ee29f772a505de648f3d663677f5d11b1d2f784c8b7c6eff3a4aab2a136a7dc09c31b8563fb7a1f6536f746da9c39a4" },
                { "lv", "72ef7ec997e198b219f4e61264ae6b8e434d38aa0cd5b28b58ae66f7b2a0bfce215fe5dcc8079c1db394a0a4939b8133134c8be93397dd19a8090ffbd519bb79" },
                { "ms", "4e540546010bcb20f206bc063b756beb6ee9ebbdb6f522d4807b570b356b0acb7d516fdf984a4d85efd27fb03ad66437bfdec0356d650332555877d6a3bdc57f" },
                { "nb-NO", "539fbf2433397c7c0dccc39f16b6ee996b477a909eb2f9defdcdb84a261bac92076bbd45991ebc4745f47e42e0bcf9ce0150d6de05b77d05bf95869ca45d67c8" },
                { "nl", "ccfca2e3083fe194d9f35a5b11c3eece6d40f279aa993dbbe6e2184706b2e5277db263e0bf9b51a8b47624d5334e8176d48b75bc88dc22b78b2eca1e8249e278" },
                { "nn-NO", "f9f8bf88090d1afaab24c9bc47bd0b630530dfed7ce553031f1924fb6bb42e218d281d4ea3077ca57457a199c31ca8cc9f0c522c953207d0a28cce2f34ef7028" },
                { "pa-IN", "9160497047e72d4f5bcb92dfd1f590bd147425d687855386ee34ddd9a97a68181b45b49475e924d138506037375a5f9f805527d3f76656866cc4adbce344850e" },
                { "pl", "74bb2c8e32bffe732898cf4e12942a450fb5b314cd018f5e3ec654dbcb54909399e29e3a62ce69b38f2c76fd2adc2b49312f1bdc8774cfeb10098db5cb6b87e1" },
                { "pt-BR", "60dc53c12f32b044c68c39c5b38effddcafb7e1a8721f8103784fa01e0406cc4245d5bc5e3e4386e29eebdb67682960bc375ad0fb1f96f02a37b5baf933fa827" },
                { "pt-PT", "370828b3c348e678867c9b7368ac68265fd7df7fa90b10cdce6b208b18cc36a694a598f95965ad78b7549d2fe47ced06ba25c3d097c0236a9a36f61692143474" },
                { "rm", "46fe11a02123e6e8da32ffdd45f73a57321cda2a92c118c2e5891c06ea7ccfc9e5e129bbd16e0ab355ee599bbc230dcf9c2da85886ff4abab19fc60f03a0841f" },
                { "ro", "9c80c33c5c9b42caea345efc90f3c9d9a827a17caee9eba848b353cc0bf3f6c71a2cc05c342e708a06107c4e5965c2e6b444062b249b1187cb330d75882075d1" },
                { "ru", "530c4abc249936bfad46f756d01ebe5b79cc8bf1daa8518bf6b2dc19f59aa7f730afdba4927bc739c67d5f8bccf3c30d5c9109e4a08f973dfe690bc0d3bc331a" },
                { "sk", "8b00d4a4ed12359849aab79e340dd052d141956327f300422382603532e824485081efcc86261d80bf6a195c505c852c219c75dbca0c8f86a21f37b72173f3d7" },
                { "sl", "26c91cab53bdb59f7d63d218a5fe8e651da161891f31cee3f09371cd0e2f5e8dc79fa18d98aefbe6c10a63e72716126948ebb04ccda7d30b9e55b930c6e7d336" },
                { "sq", "e221b0454489c8067ec1beada2b954c9dda4bd26b8955b94d2ae86b968abee0fe4b05772b7cf9c463a834e2aaf2dcedf58fba7ed04d05018a979d654eb45f3f9" },
                { "sr", "4deac5dbc2e103293de397de45158e3c2ddbb0eb6919335df01110edc3fa5eb93181d14cf7ff969154dd662d3e4c322af4a3f419c41403f796b00e998dc7be75" },
                { "sv-SE", "786b65c4ce84896e1f78af142b7a63c02e088aeeab6a1ea63e79e6c362f76e695ba5b99f38d8389aa8e9657dc3bf58073f5f2343a221b3203e8b7d2f4091164a" },
                { "th", "93a8a649916237592c91c642b71e594d14f8d691871df1aefad7f471303a1e9a9f0ece6997c51e65c253a829f79ced8072628e1ed9b71127e31069bdc40c0c1e" },
                { "tr", "df0b98d5dc77e21204fe18f1c6fa8f023b70a77bc86e2832811faf22ef25f74bba2f9e234977a3fb1effbb73fc0802cd6624982d037519ddfcdc962aaf5b1c8f" },
                { "uk", "865efca8977f907502713b27e66d5bbe6c0a14b608b9e5732ab8b1756df5c200d782ce6eea9a4b70b47966899d80b850eab7afa417f5aaab8349a1fe665e7d12" },
                { "uz", "f82b73240f6efc0d1b501b332e68e1c2ad0ca0f45d7b1bbece2772a221c4acd5fac953df96435c3645ff05342fd1b3d67cd0f6a010684bc2e60c7fa2680a6621" },
                { "vi", "03635767ac1ab9ea7f1492314ba9fa1e6df4886bf1b3e73924488c08cb04637043c49d4884264792f7ccb9830bd9112aba29d42c246894fbe2cd0b983e6a89e9" },
                { "zh-CN", "487c87a2f85410fef1055f237f52f92ea237c16eea542ea3d50c04d7016575acacfa68d95dad85074e9139a84275f2fc30e8c2e24d37940d63cc56517815a5e7" },
                { "zh-TW", "2788f599a9b8d987917039ae3d71257c5761f3b839578450d21d67f5c56773eec30471e2890e58f8f7eff6f9606f8711a48e37bb17b13973f81272b0689639b0" }
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
                string newLocation = (response.Headers.Location?.ToString()) ?? "";
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
