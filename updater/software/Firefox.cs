/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020, 2021, 2022, 2023, 2024, 2025  Dirk Stolle

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
    /// Firefox, release channel
    /// </summary>
    public class Firefox : NoPreUpdateProcessSoftware
    {
        /// <summary>
        /// NLog.Logger for Firefox class
        /// </summary>
        private static readonly NLog.Logger logger = NLog.LogManager.GetLogger(typeof(Firefox).FullName);


        /// <summary>
        /// publisher name for signed executables of Firefox ESR
        /// </summary>
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=San Francisco, S=California, C=US";


        /// <summary>
        /// expiration date of certificate
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2027, 6, 18, 23, 59, 59, DateTimeKind.Utc);


        /// <summary>
        /// constructor with language code
        /// </summary>
        /// <param name="langCode">the language code for the Firefox software,
        /// e.g. "de" for German,  "en-GB" for British English, "fr" for French, etc.</param>
        /// <param name="autoGetNewer">whether to automatically get
        /// newer information about the software when calling the info() method</param>
        public Firefox(string langCode, bool autoGetNewer)
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
            if (!d32.TryGetValue(languageCode, out checksum32Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
            if (!d64.TryGetValue(languageCode, out checksum64Bit))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException(nameof(langCode), "The string '" + langCode + "' does not represent a valid language code!");
            }
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/134.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "41bffb0aca9ca7a30d0f8d11c04753c21dd862c8acdbfdf8bf98727ff905dcaa120ebdafd834284854df713e8ac365f4a2d80afa69bbbfde0c01d2967f687f4e" },
                { "af", "090120792413893946614dc47580893632dfc63d9adaebb40ff602dc5ae6e910d00b2adae86e341d095cf5eba934b18d625ed4110734eac380b8f6f1d0a74716" },
                { "an", "d47f2016c670e95814117091c69d6dfe02b2903f62fafd5a45df2027f2ba99d0c8d7763d91d96008a75898b48a989cc720db4cd4dc5deab19a4e3cbd22d1b696" },
                { "ar", "e0717aed18980ebd09bd7bddd5bd452cb6f694b07b6c04b8760ecd9f78e9dddcf4b64c41d3a3b5f6c25ca59c24e873d87863d88af371701ffa15bb898e3fb4ce" },
                { "ast", "afec9f5fd0badc3275dbf1f66374c36a03835383f4f088674e9cc8200768b96ab3a4344931e95d784c5bd582f02d6164a6ea8a1240273352e653e22608d548b5" },
                { "az", "b1270266b497bd1c324f59f7552f6bb2238756f0598cd66bd59cb8e3773ca36e95b017b905019a16cc209b73acaf615c0438a0186805255422d0a363408b9bae" },
                { "be", "61d6dc9c30f4ed03127010914fdb4e76a3422b36d6e68677353c05d47f04849c6f38befaed6a7d56283b57b3d90111a9a370e975a80b0ce84adac632875c3151" },
                { "bg", "b8a21ae5211ec6f061988791112664ab48de4fd01b38ec0ce4e9f36fdd72a91d08b5529c3280f77f629316b801e76c7d8def7b23dd853aa42d6505d1229caf45" },
                { "bn", "659db69b71d8e36504e5dc6a575d0fdcdbb40b94428257178ba3bfbeb5cd287e7354377d71fba70d727c8649a7c6aeaf235dc8484229ebb2f2ccf5165c812b82" },
                { "br", "228d7c1febaaae41e93298a7504f4a692bb225c7db93f6e8aff2748a15d2fbbafaac80e4bfda6f9ae4efbea208b20bd28d9109775e5750b55d4793f1425e995f" },
                { "bs", "22c96d6b82105f88cc1698c5a7f70ca89ddc5cfccdecf39c53a27e1a5a9ed9c7926cf4a83632e4f96c6b5d58fe344f93c9e08863d0c46714eaa3342fd36d2f9c" },
                { "ca", "8ae5afecc8d34f28b8eea4cf5a136da43f41553e5b2479c44d21abbf9a79578a80f0b091a7584d819a3c606f9d3ebe94db39ec6b63c995db31ae3b5d8ed651a1" },
                { "cak", "70c9cb1c6754822402081f0ac59bafc17a78163018665a7723a953248d62ea7fa1ad22862d587c7b946f20cb2e791676f9252ec2ce3c52cd23a1b8a62041c64d" },
                { "cs", "07e4826b2665b2c1f9e8fae5b0b0ec434935cfccbd42962a25cbae890a81af43cb467fd4bfc490c251b3d7c1b03d12d00fbf7f8e3819183d8d6ec2d9b4c9c75e" },
                { "cy", "03d3597730c8b58b352097758f6611458859932c44c32d4775227900c664f947e723023c341f00011579b183a1eee2e9ee83cd1c0936e7247098b6ad500a11ea" },
                { "da", "c7362852fcca4150824b40cbf374116b34376016812f9372dcb96d14748f96f4cd02a4a39b509138d9daa14c06bce1413ef3762b024157959affb16460cc6d01" },
                { "de", "67d30a00e5641f2f0019fb1dba6909ce57d2da91500cb34aea77a338db726d67fe1557ef5391c9cfc216a2d14a98b031306728b0490c158948671ada13ac58fa" },
                { "dsb", "8a0c50452ad9fa89d36d2b70af061a478c2d4ba160e7e2fda62ee00abb5a7a35d61d71f91dbadd717d3b4b6102908e04924fade37d9d87194f51853fd650a7d1" },
                { "el", "a8f793342f278d8a2242f3f352c02fc368786613fcd0be4cb834aad63130b2f176668bf31af81668ecd3c814e9b981658c15207a00ddf05b2567d064cc13beba" },
                { "en-CA", "3f739f33bd2aff6e1971e6eaa4346b3f4fa24bce737d1a9ced82259102fa8bbd73d9b36828a74b7e2a6db8ad1fe078614e9df4e40558d583c2e5eba919589609" },
                { "en-GB", "ecbfe979645f3dbfcc8ee676df97a2e1ed91c85394a4bb699208540b860a289175b733f8841df1c276eaf4ed544a1193fa1e0d95d299aa6c7c1a80afd87d3d89" },
                { "en-US", "62bf001bd5e9dd9650f307efa6bc21497776fe3eaeced9ba33e9577d44916ea1c2e98f81baeb6dc98ccf557f3dac2669365b72e54d8c1d2fbee1457beb66a590" },
                { "eo", "49658cca5f0deb260a27f3b8a5cb30a8ae8e7d704ff9eff38fe645476a4766760d68db1640b2f084c853360c806c03b185459cef98bbf6d36d3107d822e82a26" },
                { "es-AR", "bebd0ee233355f0f10a6421098aba5887ba6a778629354b0ce0809e8febe0751c36ae91ed431a10b687f4c28af972f81aac7a5129c440ae47f85be3f38ce6646" },
                { "es-CL", "5a65bc9aba42bcaca994824d680b332a539904389710d25148a578dd4f320406d598c6ce34007db902f7d78d4488713f40df5d9f432690892851f7b9c52a5262" },
                { "es-ES", "85f3a08196bfe8d3a7893ade373b0d3856977c7b76f722f06f52e9b6f3cae8f3ad2da25b24ba84dc99c4d9ae674f5d58c16598587284af55bb9105c5090d47b0" },
                { "es-MX", "f6022371d41afe564cd137361e5ab470c87b4ef1a75c0c2e008eb0e14d62acfd0562182f84d2f24ddfac6d276f7d68ec1ac280fe45b0cf85c5b054be6bf79759" },
                { "et", "9e45f48f1776d22c612d61f3cd96bb0f0fb858ce24d11458871d9fdc9a4d8760ef6446693ba2746939adea6d05ea24618e7f8a0ceaa377b0103d71f74edc7665" },
                { "eu", "0b83a1964423d4e6be46b956ccd37409a20525825bafe5b28cc596679073d5e16bad83f34c929b55a9c8ac56a2edaf24792d4ef2be2ccec1123dffea749c5251" },
                { "fa", "c058466c216c013472b869cd49649a43f01d4ca92f0dc2196d554ddb16513b05100ac6ab151664e35ff63de0a3437de74abe0aef7285739d60991eb0d2b74bf9" },
                { "ff", "f3c332596175b2ccf88014fc0326d730a7f3535bd0758b091d83d06a8189ebfb239844fc21ad8dde14f1b7595faeeecf2e3b38131e5fca28f98da854ce7c5b7e" },
                { "fi", "f5a519929c4d022044510002860dcb7746616a67c9e66864ee58e1ab63379a9391773f8776cf0159d5fc5aa864f9199ad449d40e9456ccfa3d43093c6e26bc65" },
                { "fr", "6600284e16ac957ff783caf9e555a8f925a0e39cc456ab1d839466caa13cf04a7b2da5745a29d4332b07525320cd232ad49a0257379579343a588a6dc80bc40f" },
                { "fur", "1f861438ec13294a6c92adb867f4d85dea32b5ae196c2bf646616dd12bbb0f20b22262fbe88323cfd0c861d4103adc0c9ebfac8e8bd0c46e0307fb90462dc80b" },
                { "fy-NL", "439c950ab8fea5030b8f895b232536f9605203f38fb7cb787d4727fe8039fa7b02997be64bebeb0cb89da225f4d19ee15661d77e2d7abe1cce8601f6c55a2f78" },
                { "ga-IE", "1a995fbed55773d0c2a2dfd6936ffcf4fecef3aeaf75f24d43a3b7a1f192373c421963ae1e65e1f049c1fe20f2e4285ec8b08e2cb31d4e875f94c464f08312b6" },
                { "gd", "29c3a214c8c7b57d66144e3e95dbb7b9895ac24000a20837876570d2f8308446a01263160094d39828c06d1a0c109ca5724f76907808bdd7b695f02fcbcead28" },
                { "gl", "fce35d280d5c7c0b5211eccf6298dae2f3fc1a10b34e2a093a825e43760732d2d99e1f6ae81db4487422429ea18ccf04bfb8a09fe2ade35f42cdc8c9dc02b856" },
                { "gn", "c8ec197322ef390d6cf69ca89ef3e7042d634ddc8c54d1445923b89f3b2816f3ec5d3895e106196872ec681a5b40a36d49c0e7fd0f94b45dba6cadd5b2e2606b" },
                { "gu-IN", "f92bfddc42be644813a6f6e09709f3095f8e62d3bf569689c9213a73e50670f48a3e3af7795ca37a0018466c36a200181d687121c12bddcb4f7f5206a22c9a7f" },
                { "he", "3555ed8bf55f8cb8fd3ad5a8fa80b1a599c6351d4149c6384c3cfa23495ed29ffc7b29a9848bf8bd797d02dc5b68e71a9d80e9826911da1295528969ed1c3481" },
                { "hi-IN", "84ab0bde5eb55a4b56f33570235de89559ea8e241bfaa7fcf5475026a895ce12a8d7928352ff6e751a7a139ef79f254623fecd6a6e84493ff8eefbabbffbd6f4" },
                { "hr", "9a017e6bab91678d41b3a5fc4a9d145192a12aad8c4db39ea20be08a0499f374e3030dcc847ffa17dc942f8865cd00e0bb3d682c67830b0a6d54b7328d45d604" },
                { "hsb", "d5efee08c0f5a4a07294717a293f21834b56f3ee92ac1ee65985eee53d8bd00f9bdd7c057f32ffd45e45a5dc4648221d4e59342840cc3f58ddbe375975b7decd" },
                { "hu", "6c0151c92b3cbb095228ffdb3be493f546a71603e62fbaf5bf93ea2d8422132c25c19d44b8173760f6e9669db711ffe8ab55b80c4f2a3a7551eb8788f0abbfde" },
                { "hy-AM", "3742451865a0495b0097202467a357b125022671b85788879705d8ebce04c52805aa6b7965c74a21b75f2814313fcf223231cb23406d285158435a5a88cffc50" },
                { "ia", "f94f6858c7b272e7646bef4731f87f8f434d71e17000f55082a5d890c9677e58aa4165b3b8dd5a535e08585d6a9c9332faffe7f1593ed92e51a4c3f5ff12fd18" },
                { "id", "fce1a1f99b11f42489350210107af9fa3f09d4451ba3fc72bbf4343678756ef4af70e53a6ee9cbf473ad7c110eef86b95d0261620e8a354aba73d2f12b14b02a" },
                { "is", "6cc0992ae5ad80ef4ce0ff3542eacdac0d973c82820cfa9d40e15274ba1a5a7efc30a8f528fccc67c92687a29bd7a1662c85d912c45aeef75722e50576194683" },
                { "it", "7067cc7e67233fef1bff2225d16558fc4cd882d32d247d326f7b396101b09925d9d1bea12df9f9287b2d5859431e02e890d549011c0e6e7d7ff6c63c8b2bee13" },
                { "ja", "9bf16429455dacfcb3c0dcb42ae0300369806062f2b5335db11d4879c59455cd13cb582411a12e3325ba254db5d2cae34ccba0632277bb444ab4b84d9ba8c091" },
                { "ka", "ecfa33374a112034f6ea58862a9bac15dbaa393448707d974d04ca33de674ec9f0fd606e23ad9a56eca6ecb6ede6da6c82f30e852b49ce0ec822351f5404ed0d" },
                { "kab", "094e734b777fde046832958a063ada55592bd5c08ce77b367f2b35dbdf3d9b7851418876e90f9a9ce77520c04e252fde389182b6f9ed92d73908ee3330c132a0" },
                { "kk", "6c731cf62f25921196715286764331ef570dcd8ca19d958731c82fc6794ea1ada6b5761067294c577aac7120aeb7bc940234ff7669541e0e3eb3b6e245ed6cdc" },
                { "km", "e67932be4dfc313820ea6f46ead88090e462f110d6108f776e98d4db057a403651fd5b0565b31845bb3c7aa404f3e4b19b36c9eac25623fa1f85b2d53d9aaeca" },
                { "kn", "1fd7afb7ff25c3ecc858ed515a7e343c33ed666e4bdf69638791543e67097d175b458d3eb9c0e8dc8687821f061c4060646a542251675b4d9316e1f6bd6d6831" },
                { "ko", "cf47b38629009488b3e44bf075a379f9b2c4c4107eabcbd5a0d3ecb93fa6b8e93cd8d3101d4e48ec7800c1535102ef9146268e8c59c58a9cdee0cf2e806f6074" },
                { "lij", "76d4cc1362a039088c6b6b873b5294bff0290056672491dec6e1184f1948b83f74e06927d61b9776f4b2c8120de2d50acb2efad09f4dc222e1676bb3bfaeb35b" },
                { "lt", "f5fa0cc4bb574fea37b348b5aff9cc0b821a5fcb9cab0281cc0cab8a7c49cacd4907e32f8ab318ba441fccdb2eb02825c998a717de36e047c9d76464b95179d4" },
                { "lv", "6c66138fa624b21f8a1f1f6fcd7b94a3ba72946d0dcd3ed8189f9b0011e70360e46c5195f39cf32a1aea5193f87c98732aa50edd340d0a84c20efad16e5ebeaf" },
                { "mk", "6e3a61203bf0761844b9268f6d0b8241919b2b9005fd1b6049aa86a81affb9da9a827e0c07c5ec38c9e8a93b81fe63e906156c2a1f4bc563ffe24debe064a670" },
                { "mr", "e8bdf31aa360091220fe447bf9156ab9832b28b22b3344bcc5a20df631e006099cc2861d1af22b2f7a3d8626aef8c9937ebee9455faef051d7fc86a050dd2028" },
                { "ms", "9d5fc9b98408a55ade83ce57036597d92ed51de3664262e0f9cd0aceab8aa093958d5ff66f2303fb44eb344254384c4c0df946dcdc28ba8f6ee0bae39f3a663a" },
                { "my", "1726be6d0c7e165626c5ea2e0137622ee3835830fd87cf24140fcb6390a6e6361483c1d909db7675dd937c507405277d8154c8d32a63c0f58d17366ff151f955" },
                { "nb-NO", "2bee7fad2debcffc398d666c04c33cd85cfb0bf6197d4c2ef85fd3e70420096bcf932bf3f854a7d097fd58eb34304549c5bad17642ae995e91e1292eb550d0cc" },
                { "ne-NP", "af42fc225be78dd338889ffe081d39df518483d53cfbf75496b3335d49ef8f806b639300de7cf0914e4d08407abf0f617d36d21d5f5ddb81c2c2abd35d09ebce" },
                { "nl", "abe9c8891b448616e5faf2ab824f25027fd57c242eeb0afcb1538f4603206f821d8fcdaaba7f52297865a17b64fb17935fc78ff60274b94d2d1984ed2d0b25b3" },
                { "nn-NO", "b72c751c8509c61a5d0a6a275b676a6d39625723784128dbc27737493c6f0b4292cd35543f38d657a1ed0bac890ecff1f7d47306c0254fe18d5343cd94833c8d" },
                { "oc", "94cbb87b6e9f921a42734be00b475cd971cc715215402c5e2e252de0dde5852802beb778215537ab015c338e96ef042f5538533fc1343d5c3f1901ef4f77ee49" },
                { "pa-IN", "a1405711066748fb7e0b3e6bc1799d67d167e46a83e264e0d6c8f5ca65abc0f3f8590713dfc120c74cf8c35bc9d6843d195fda08a08ac6c3b92f6a9700845888" },
                { "pl", "cd242e03a0d831b04c47bbe3980b5d4829044912d1c61a69627af9b2b0066315ca07afb352aa5ac5114656386af0dd8bd727fda79e68515bdd5adad98b27a81c" },
                { "pt-BR", "594d0db8c9eecf4e74029d928f0c6f33a16fba79f98aeaf22671a9248022522e85202f9ccd5c5e49c527c4676594f05e42f5854517a9c9c85bd952d38ffa2bc3" },
                { "pt-PT", "c9152dc7f51c01f9a9f4010e951b38e57ad2abe00d26e5868e36727148a88b5e08c37865bdb08e1a976945b0730729ea392750a0a779604829511b53190c4e53" },
                { "rm", "a44223212fd0546781ae3debc635310be629a2a0d4cbf45ed6dfdbffe102257952881666b757f6624b37392216423a1daec0c84373ffa87656ea8d80e38f020d" },
                { "ro", "fd2cb236be1227207958deb04d6a8ef7e74fda6086ad6dca47d429d325c6c91996a826768d83a24716f6b0c333e3689fa58518a6a195f35704e267e49184d762" },
                { "ru", "b9c9d45c4c88f4e17d9ee96bc446618ffd645e85cd688ff0770d974f3dd2a43736533c17cbf6bbd3c3eccdc28b6a68ca2095c30aaeb47bbdbeb8d0f1cbc7c956" },
                { "sat", "00a0ad264c510e7011da246544d71b691a94ff194b8c66d39373bb7e4ec782c79c2819f1ba50bf83701acce7a59c4b26c492cc6928bdd6ec289ccc426ff3904c" },
                { "sc", "d251c6364dfd8510a72882cf912219b0b55a63f6fbbbf0650b5ad364cdb6a489f05d1849e9737576f8f62c935edf31f6f52893752c3da2a8b55548fd0fee1013" },
                { "sco", "038e7b405f8e9a9c62c28322a12f7a48ce8e6fe4a8a537c10aa2612bf115b6198a951c5e61750b2e8586695ba910ac03c8fcbbac62330a1b5c96704613d1ef7d" },
                { "si", "154aa16a722c7a68ae50a9afbdec6d45a34f51225757465e2ba2ee42843da39d33e6c24f12b6e0190a488cf2459683b44a924f095d4524ae0a96f07a2f9229d5" },
                { "sk", "46c5b6ac9db760d825011571372964d1d64c6aa97117cea5f56009d39d9511292817b4d101adfa172fff3ce45f390ae015f90f8ef5f4b4a25b02c518435b5c65" },
                { "skr", "5bad560db66cbd959f72e9ed8dde28029444b8470daaec86d931826d41da198ca9ed4100618e18f3c5ad319f218fe64c403af337913c0744a5939c42d90c23dc" },
                { "sl", "9cc7eb84c38bbff7d1bec049551f2d0b82498a13db5cd4b33e51b61e02878e79b4fea25a4ff01cef3ab8a86d7ccd9f121dce409579e32a4bef6cc4b580c0e58e" },
                { "son", "a6006dbef343fd283deac8b2ca8266b043bfc0d0c7a7623b0d2d254dd66cc0466b35430d002cd65a32a8e5683e1e2dc254fb23059742b55eb7a1d3a42427f9d3" },
                { "sq", "6bebee0aa3ce0b87201d9e0969967f931e0445577770d90a17f160a6a455841d34e386b135ea36c6303d4b5b5b980617c79563ac8f55341743743c0571b72f1e" },
                { "sr", "a1867cbd18efaf5c8d00c1b51648d8e1a10705664697f5442b548fcb24e7f31d3a1b93ef1a56668ada694a8e94e651b4ed85c8e8622c4bd6cb1619f70531d268" },
                { "sv-SE", "42c1f7f48461d383dd5c1c08c54e13cf262b72e476f48c6b0350e3d41239c98e4393422d51efb879f1ce25f7ab94be39cdd784f388463eff89511f2bbec7f565" },
                { "szl", "1fef4f90290c79e0639bbabba57deca5d9e1b54005f4b47addedb700e600f8ddd7d2979a8c5581d2ca9a58a06e31fb5fb33ec6d20049cacc35fefa53b5376078" },
                { "ta", "037fb88f1d7fb2ef97a3ede0c3d70d7a6c6fc3312b903070acc3c920680eeaf5d8aee4807541bc05ea5a3c3971dc55796caae3322d9fb653d6d8d41b32e0ed4e" },
                { "te", "1b1e64ca745ad49770bfc1542b2e364302465e5c1ebf9cc6a98413dea54ed28bc3ea1bfe406553b452d88d1633643c551d9914a239f42e873e2a7e6e80bbd25a" },
                { "tg", "5ec5113148d4f4daa2acaebd633e982c568eb986c3c88fc30bf2f1b3888de892154fe2584e5f87db1108e4d693761d87bb6afca77e0363ad2a64106912d401f2" },
                { "th", "804b7684289b77bada1ec9890b282e440cc982cdf13228526c771509f1169fac3d825e5996ca8528f0c904a7acc88b7d8a479056bcacdc86a85f249b2a3033f0" },
                { "tl", "51799defd1f161ab5f09802240600139e900a385089178b7a2590c0b484d5ad032582c512ae9053129f7d8ea8d79bcf954be1fc9f5292fefa94a010409abb7e6" },
                { "tr", "f96bde05b0b198a5819e69fda54be4f76127361bc519fba19c583d87680c997bc3aa46da9add9933937fd6185ed5bcba486672d06c77643a18054ede73b09f66" },
                { "trs", "b15b886c83e74085331e4a73dfc58ea100c207f3bb57c7c4cb1fb0c55322fc14ddbc6fa58c5f73bbf5ed6a650a82bcb37b3af7b1942bae0a9e6709efa35bc9b1" },
                { "uk", "82816e4958ecf476c1697bfefa7acadc322d4752356e24a21325708cc1efb309354b28d5fd796e60d230bdf0c151bdc0ab5b018e9f2db805809d7872e39cfecc" },
                { "ur", "f55ff410a6965a3a5e2ea49deefa031111a5f0b7d5e246a6331dfe089034b966f967721d5ad9e56fe57cf6b779fe8f3311eb11f9dbbd47db61ba698cfd5e9480" },
                { "uz", "a0bf412116e8ff1b31952295466fc159261e482a63261801291f70650023d6df9678c8898579d77d3c4f375deef4aa4bb015e547ed8e89735e8f47c176d5f814" },
                { "vi", "12c828b749ff310e266a61058218cf492ed45c94cf3d6034d20597338280157ee0cd49aaa7a813a46e7b6923abd1f4d179c8fd11799517848828fead44a47b32" },
                { "xh", "0c883c2f593c695bf526d88b1a6108ca5ad7c0ceb9a967a16e62e221eaa61f0bab4ccbe8a2cd5c0d63cf470791e491c90ed468cbe41164b4d55d8e3175ffa7bd" },
                { "zh-CN", "a14457fed29075ac416fc18f1588caa8610d1a3a312662a8060b5b5f59b836ac3a2fd4657e82872b5c785932b793fdc930980f37a3d36e4e9018397d3cdcd706" },
                { "zh-TW", "48e124d0732aa86cea8c64b6ccc7317657a187472bf3a294feecafe0e963a7112c822a60a040c08acd09149617190bbf98c5aa85c57535f62d35e8b21c7931ac" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/134.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7070d1209903460938222b3e614be3b618ed79b3e43b00f437a6435923348ec177103e2903f71da2cf111f59e4b37c86b7a433ce20e7d94de5b6ab0c4e94da25" },
                { "af", "7077c3518d960c39297839057d0e9a70310b4a6ddab79d729dca6e39e72aeb27e7a04f953467b05c005f7c5fc6b4fd21b0356db6a0fc8c06ca69761d730d0d9f" },
                { "an", "e94efeed5fa0f30cc3a92ba7ddaf9a2d081695bfa0e6d2a7a5ff8206d951ebd6153020a8e911faef08c3d0ae32219b97cabf7f4cd1f7879164dbdebf56c327aa" },
                { "ar", "a3dd8ada153deeae9c93b9a4c8cf51ec01bf9bfa029957383a4ffac04c1b8eb75e86de612e4fe35490dacdbd6dd2d838c015ee4d3bd5ba293720483fd16f84f7" },
                { "ast", "f33a29f5d88c8722af7945283e986d738d2e9c0d4c6dd6c609cb35d18527c79398fb1ce531b9218d25de6750eba7a27831bdd83bb419380769785fb63745582d" },
                { "az", "2887a8179a3881c7c695344835b614be9581609710bdb35d7a43517c9c25c8c61a3320cec9abb6e7c760701547580c5b5de69be0f3da916a9b4a77b07c66c38b" },
                { "be", "3742a6bca3298238ece9044cd1c83448737ebaa3d1c55a43794f7ebff97cb349fab05143e1577cadcdb4be895f8806a5df78cdf7994a54c9a7fd4eea6b78033d" },
                { "bg", "87131816f29c64404e05718268075ef7d550738148ea37ace58948711afe2b386697c8aea2258e1ec4658e06833249abfdc1f61a9e6270a7bb417307249c7670" },
                { "bn", "f7b3b2f7e91fefaa330c4b30f25b5b13607b5988ac6d23f2a5de88a3f7c456f2cb0967de217c9f03bb5c81a533daf3a420fe06ccddb09d70ed148f060ee0a777" },
                { "br", "2e9ef77633e050bd441278db2dece5e17da6598058b30199ace78547d4a15d1e6ec2d7ad47bcb8dd05ce3a0a65880d086d78c24dea9ed28033c6cc227dbf27a1" },
                { "bs", "82e85ced134d428732ae9c77f159c678255d735533d4a26b3bbdfdafd289e39fd7a08522cfffcad98b0cfa48703b63329c10430ade6fe18670ca42adc89b7c7e" },
                { "ca", "d011dfffbbeec81ea9e53f48133fa8cf8dd79d7ea5f351ef5a8a48269a2123f7834f33f7f0d8cde902800afdb73d2f64adc45ca28c23248f57ca2e7aed31b9ea" },
                { "cak", "823c05cac11be673300dd5039f3351cfa37e1c1be3945fd7de7348d15249fd8367cf847d6a210572ef96f1b8b864fbb7c7462dcfd3973ae8639b2b064cd08406" },
                { "cs", "da07c0effca1f941d5a574d22a9a97d70579509d5e7509be2fe23c4b09f83c95ce4b0d2688d40a37dfce978082ba8eb018bfae97343a729aa8cc95668daf79fd" },
                { "cy", "5db26333e85f40e8afa3bdf3e5271db28980dc03d43b1cd9758d576d2c250a886f80fd43e9d62a2ceb1be8f61bc1d685e5e8b13ebbc25572d1c5119805495c59" },
                { "da", "15e3304276ce10f800f606c3fc40ff54745866a76df6575148f8a6c4407b95de107d89ed41130b8dec8ed563706cae6ddbca298bc43cd0828702d34c738335ff" },
                { "de", "8bc463c72bba929bbd01af52b08618f05bfa013ac0ac321e627bedc49916aa6a287f39e70e83b7d2bc435aed1f9456b58e9950c8963db4f5c7eb8a0114ed69c8" },
                { "dsb", "22088fced0a617edfdc90acae35b6b743dbc1394da48ff0624a3e7b72ca6220fdcca49209a4e4b76f1b2b086b2cfc023a0b1de976b9eae47384de34161799e8b" },
                { "el", "59e1570dfca054063f5137a61413000dab3d1eb4d50059cf13067bfdb2314fa0d680d1d2559b5a03813f7f89d608e3827384021539ec18c2073641fe0bf0c012" },
                { "en-CA", "ad152e562f3bd0d71e234fe1128a2bf0d2c5cb0626316fa40f1d4c809917bd9a8e893101286edac9641133e3da92885a2112b15c7f4ed86ad7a4d89ace72c13a" },
                { "en-GB", "2639930ff1af82cb61e6fc966bc0f48190f08cf5f97b7d265b0d312af00520c78a83cbecaddb46e9dd7dd29783a72cbd5d2c81a17f033a2ca836db867b871610" },
                { "en-US", "11a471ebfa646ae0e6805e909be7150d30ede6dea6c97d0ccbfa971967a9f401b2daf78c4ba64cf74aa27ee68a1908f432b68cb85d9e1938495e6e35d57d909b" },
                { "eo", "7d4ad90fac4a713a9f81ec1ee724f32bd5d281eeeee41262d61e4e6b83135551e1ab071ae3fedf90fdcf49109909ffb9d7beefafd0cd942fbfa20fe661028623" },
                { "es-AR", "2025e0fa49bae1f3dc8e84ebde5a293fb1b2e6b5a3b38d61246cd6c453028e03244a97ef3b0b15066d143a463eca98732375c1146a0c22e4c70ae138322129b8" },
                { "es-CL", "b90a3ddb12d45d1eef8a6677b02118b4a6b4fd1041c3e3d5923da13c0bef4928d497a8ceb5d6e6c52aedfc0d0c858ba6f7864f0240ef2dd5dde9402b2e30b2ef" },
                { "es-ES", "708f626fb9cff952b2125c1526fb6fa2a6de2819a4d5452b0462804d830e76a3310f891e7b67c5680cc3faea990ff2533fdfa05901b8f9218c4e745bcdd375fb" },
                { "es-MX", "e3a4c9ad0a9b343b6348f6f96db0355769fad77d01fdc79c86814f0b1e8e4651cb6e1d3b25f978b92d251ca7c8b2c51bf15efe0f31bc32028091df05986f7447" },
                { "et", "9d84df137e9d6c3dd196dfee13325e69e49f7ca74f3f8126dc3aa13a73d0fb4b85083a3f2e5aa8c8833a82af645dce3673f8a3893671588bac4e60cd08743a81" },
                { "eu", "acd752ad5c6a9733df588c3160d1ae7f83e5962c2534f2165c58ff5d81fdbece51e42073ad832f5e03c106acbb966282dd3d714ba8842c8ecabb75d91be485d1" },
                { "fa", "a792f663c4611eef6bf6ac01aed0f1d812e5444bd6ade13f20a95bf51917cb7fe2645d5592359dd2f6252ee057cdd58f1be63e4867356fa7bbf18bc3510048f1" },
                { "ff", "6d34d875d2b177159acced55069805d4d9898053093d1cc4bbd2ff16263ffbc7d7d665da69bf7126f0a71fceb55fb62c4799de73e6e24de91fce2bfcf66cd920" },
                { "fi", "18d0fb283144fad0d10db544cb1db6062a8e1ec8ab0fb413cb5f1b844dce042912318909084fe276c0eaab1ae63a1099e758e428d409a9c7497691729fc6977d" },
                { "fr", "ef950d6d20e1699f406fe4c46e9b3ce79c7c58aa92ebbbb147f632547e1c01aabe4c919d8315280540d9470db23f01e45bd96b34c5b77dd3dad54d0b9fb73d7a" },
                { "fur", "f2fdc2c1140099b8124619b28d9cdb65a8151ca002c1c2c7fa04709c8efcd0076ec1165dc7b656c564ac8706966f0a5fde71d54a2807a435b87d446d3f4f0b28" },
                { "fy-NL", "b4a8878c749cb8bcc7bd87200bcfe031798174e8db2c90ba820e412d4fd1f0cfa2d8cf816e3e5ddd907b3f80ef983c65840cdaadacd8d5470dbc77e4fc99972d" },
                { "ga-IE", "0fb2be05907dca482e7444711e8c18aacbcf858ab0c015fa06f6744abbf6ee6395fbb9386f01237f90bbe942631cd67082ad9a6981bb606fca3c876a6d330e4b" },
                { "gd", "cdff050482fb6b5d5a23441c0e3675fd644edb510a7c20c4f760d1a8001b72ba4779b0b2a8cfcca4a5f86ff5e61d51a15f9e27e58021ff972adf7b3bf6ed344c" },
                { "gl", "63ec83e4fb57fb344c2cd10ff77b38136bfef6f0551713a9ce3dade2baaa89563072fd7bcbec94965650c5c0995c94edfc8ac004542c2c4b1dc64e2f990bdc6d" },
                { "gn", "cb96c14c208acbfecdf318b1fbfc25683a967043bcd7346a22a2f8dd308300c669e3a5930f1a8facf907fafd6a070ba47b7dddf4639aadfa04453f5faf678c6a" },
                { "gu-IN", "05a83d3a45a55bb6613cecbdceef7f1269e6aa2ea87c236db09287a375c2d2905f417cf6ebf6799d20c8c96d597c7339dbcdf710f41b50ceaec4feeb1ec4c0b5" },
                { "he", "81226e8a3b6dfb6cf0c69bb70c5524e26b29e3124635cb186e72ceec906463af52354e441b7385c4df2560cec90abfddb58b497f7996737325561db9dff9c6dd" },
                { "hi-IN", "3b0d15b3d1ec25a8dd2e347aa6146fc8f2fd28916adec81309a2fc9f46752ec84ce13dc66446d3d37156bafb706777c619d01a7b80cfe7862a2a4da5e798c61d" },
                { "hr", "9994b6656564ad7bfae7d3b348d18ce054713d3e0dfbe444c8830b25c1fce7842a983992c82bfbf5e2f81167c7f6f52f53cab08ac99dde7eece354578d6dedde" },
                { "hsb", "246d7f6dc284bb711000fd00af367e9cfaca1fa1681432e65bb8fc831e980de1dbfdf247969a545fc837c2416627722d3e24d548233d14d8b1323d0f70638b2c" },
                { "hu", "19f0446769015046469fbbfce93c0297782c3e4c044cab061ccdc55ce3d8967490ee6eda859b1142c7016a982d9a76c6832e15999b0519d73b3826145ecf9fae" },
                { "hy-AM", "2e8a78842acad80df2a4094545486212741962e6aa958a0980f38f6f92c9e69f8a4845385893b9d5fe8b57ffc4185b5c71940d131864b051761ea4640e65776e" },
                { "ia", "45ddcb77df5badf9b74c76b4a38b58963b3bd79d4666229c5d43320cc0a6ca5092c25bcc8fa86213d1ee45d77c7a31371596e3773d8f6cb9428607a8b9ed7824" },
                { "id", "46329728476b1d779937a8e7aa03aa94676de2407f1539c217e9ee69ba693541b21534f5126cfc3215184c76b9c368dfd184d90de98b1c193a1170d7f56b8bc8" },
                { "is", "50b99c2178580a146b6fe3bbdf4c47777f26c58a90a489bc1dee2807e65215a6cd1a8a24c9c55c3b186b82c6fbf02b193347016182250524d553c06dd40c21cb" },
                { "it", "8751f8edf273857301552694bdd21edb7bdc78b877959e5bc344fdef76bede64be987e83f2ec976002dc75dd626c1c14bd77547ecc97f23d94fdaab6c22260d0" },
                { "ja", "b793c0cc7cfd56a7b7a92d60c5caf1d6165c8c957f16ee81b27e1deefe7d74068d5ec13fecd5bfd2aceee239d78c8bfc131adbc20a94eebc9e8d3da0d0c7cf22" },
                { "ka", "250367e0f5fd9e6d7fab16fb05962a429e900037787cfd4585eb39c7a16d87c1754c89c33053858cb408c7ff8d9715bab0731034eed3b8de0a30e05183abeb0e" },
                { "kab", "2936436a2fd0dc048419f8cca4fcd71e0542f435706f7d4ff25571a446636becfcbd3dda203c74ea3b4d473701bb99495dda4062c0561339fce54723762c4cc3" },
                { "kk", "f935929904758bcea492d7cd74fbbc1d44620a459070c3231f7526d45fb494aa44a83ac7716183aca33ea7c8c359019b3827c28d864aa36e1dea9e3a5523585b" },
                { "km", "38dee01705e11df68e64805290b0fa6d0b838eac25c3bccbe42181822daec037965c0e76420db222350c8918015f7188475bce5da15208e403a298310660dcae" },
                { "kn", "f4f3a12bf4eac875dde0bd04c460f93fe83a526b7273367e70edac0204e1f28ffb1a51c6c080fe5a6c3129035c39e286d9dd29afac723043895be1f3f0814df1" },
                { "ko", "40bc5f6d7edf88d88057c7f8e478cd5f7dabbee8c601dae1940ae89818d9c346cfbea96e37f95855512015ee39d1c8d45b55acdc70b95680750e4a20d7ef8958" },
                { "lij", "2da92f0ceeb1a9f0635647d264d5cdad11420e6e1a544d968835e23d492f44f011073e29537d9aa974bf5d47fb41eba131780fadf49ba4e989fbcc478f03a49a" },
                { "lt", "1f59948819c7e533b48e049e2bfcfa5838a31f839ad087a08396b7059983dbf253ab4a939c87f30f1a5883e6015eabb7f23db7897137ba7f327d77669043dd7a" },
                { "lv", "60ea8f6ab41411bd20e46239e807c9b6859a8623697ac31acc698d63b822ed84cd36aa43e44f4e28e3a79ee473a2b08bf281338f312df483460566090b1c4ec6" },
                { "mk", "e9ec93311d79786050f94974c4172908d09e0e62b39cf87ed34887d8a8c73a780289314793325bac8cb9097b9ccc00aa1d41fb2d89347974ad13b0c2168dd782" },
                { "mr", "7223fa2c78933760c6cc5209b36c25e5531f27e8ad920ae9117d37d8e2c05011a1b12d20bbf90ae7fb369a578208e56019890e6d185bf7ec57d78e38b0133444" },
                { "ms", "5dff1a9f4e49318c16a56c4e9d88ba9bbde8176932448f93b6d069b64cffc5b9976e2e1acd985e2ca734b390c984db6e988022cfc098ce8a8ee76b2402c4fc4b" },
                { "my", "f3d1bf5f77512315dff3c9eba39b35a437b2607881ba7b98966864c7897f4392edc108ad93168222065dec44232f8b95c914285c034149ccebd712f202007648" },
                { "nb-NO", "319d98f202912226768374b10416bc12f3b1abb9283230d39a507af2de7c599d577867184f9fbd2f98793a140d0ef55d5f03136503ea886af2298405124ff481" },
                { "ne-NP", "ea0906e283311dc72ba07104ddd7475b4d7ec3d41200f04b5ec4dc74351d68378a6ecfd311fbb11447ac89464e8b6713f0cf994465ae129a622f321f8d1f348e" },
                { "nl", "dc10b47b4b266fa56f0bc6056452571516e4b40f2e1d1c5306f9de17d1488bb7f1d91ae31c90db7bdb56521582499bdc837e29bdea10d397e06b55d872dce2a6" },
                { "nn-NO", "737825af5ccc29908cfa1ebdd8b79dddfeb81cb535d25b25425e8670a719b862d5fb7e9a2d624f802b46dff41b6893b3a5873f166696467e502205cbe763987f" },
                { "oc", "d405fc01ceb20d73b09ab30a26181ee7ed5158f95dd95f552a6ba27a3312e5af904ac5cf29d028d7ec44c19e364370971b1fb96ca7a7321544cfaa75298f58ba" },
                { "pa-IN", "96a6749c5209c0ceea43d839ecc956160cae5f221ead0544ca6ab7a5fc431ff9a62ceda9f9d1f8c90e7ea6ad267c128d1af4a5770ffaac80459a461925204a65" },
                { "pl", "fc5ab2439fc60247fb6444cfa285830465bfb5099070837bf67fba2c98ba20f9b093cd50c8bf7898ba956c79d7b90a6cb6b756f768544c9d6003833bb68146f8" },
                { "pt-BR", "5148fa23dd44e4d03c7a36d546ef32336aab49f1a38c3c89e9c01e87416b47abb81ba0bddbb796d056e2ee6b4b7b9653e56afa90466085cea2cb54ce823e2544" },
                { "pt-PT", "99a22b6f8b303b13d066d97afc3b85875414d324bd67e0a8c63669bdcf0ab93b698907e03d942ecc1c86ea57abc88fc40bfd19e54793448f8031556c6ab8347f" },
                { "rm", "65217cd350d13b8d510b435bf8f7c2f247980955380ea76d1f7fc32e58a9811030ec0df8d1b3c951bf862289224554e387ef19afdcf8fd43a3d9246e599adab7" },
                { "ro", "8fe63191d2de4c7a566304739eb7a78a8e295bc93ff785a819382d54aaf495b603d689992632970d7b6229b3063fb460e3b4fd5f285277aa2c61f5d9dfcb647d" },
                { "ru", "b14bd2635ce3e96afcec7484c4ce0641c7597455a14668ab308dbcc0c95a556af38472ab6a50793e28128d9200a93e16b0a201111253d5c84da7056aa7b9b1d6" },
                { "sat", "bdc4471b45c1ae808190d552d936958d1bcdd89559fafb293a520f65058d789d65c68bf4e1af062ca7be1555a0f858d30f6fc162b4757c7f3b75242342ad5806" },
                { "sc", "d4759833d149103bdf0526fe8956db8724a7e4848670bd68a5b8a5c3d37c61a908f64b8b80ea6797f7823d59637634875c0f18253355155b18249e9477f4732d" },
                { "sco", "fbe371d8a4af636d30d069dac4663e97a7adcce8051dd906637e28ed49738a56483cd3f1608040db5259e6d3f7c2f6d0b5494dd4d3ee114dbf2e36687596c59e" },
                { "si", "4d2e41f0c78f3545609f895d991ba049bc88bd2d79464ba7e88787aa1cbfa7a25ace53bf41ed04a0a5f841e56a1ac678849c114047aa21d77c2a146ebf2be787" },
                { "sk", "a14c311416aced138de3d7ea9957fe98649f0bd2cb328215a04f23a4cca7524c0e5de50352744053005c3e1434e3fb1bb4b86ea623b52fdedff047e12184add0" },
                { "skr", "306ae0404885b4833b7d32772ca7f59804167aa45aa83a9487598543c87e084a28841ec2627f4654cb17ca8e25e8280c9d5a77bca26a07613ef4a45697dba43d" },
                { "sl", "ca6c9452bc07b716daca1cf34b6e681bee0be36a3c9b059709cb5016f81be0442e5ad207152536baf12462709887631d5e3b710c12353b72fbe20f40c1083d45" },
                { "son", "f126e96b3e9087754f21a5af349fc30ae48c22c1cb9cb2109ab934680c951d5445fac618374b82c1cb61a25fab2956621733ed4ae1c34423f45a6f0e1f546a02" },
                { "sq", "38d9285a4d5f849435a79fc65dbdc3546c45ccba4597a75583e434ef51ac2573cef9a0afedc000a573ab5e996f79d49b958aa1764b78caf484a0bb784cceb487" },
                { "sr", "922be5bb527d53487749ba0ddcee2553accd4e7bda1a83cabf3afac6eed9789b32cf4d6801c790be0b6f3b77b89f35f6b078a8ab976161ac704f9c302949c6d9" },
                { "sv-SE", "f136f6c71c82cf2a3b9e895b621296917fb4eb798cbe28e12f63171360e7a47a84a1e69e7dfbef27c0c3467dee0eee0f1dce471fa5127246e9603efb415d2f62" },
                { "szl", "99e87db80de84ee9b4b35f495eace5e8ff559f89407eb8bf6c19e5fd5468396fd7c951f457bb5eea1e75d92aa88f122fe2761fc8557151e7a5a2cd1c90de7ca2" },
                { "ta", "e447edc19610bc70040824b8f6720b2ec337a4ea4d0a17bf9f5a0e81e56e4b9c56abbb4ed4764eed0798847863d3b6cbd07f61fc7cf0ad4d6e47cdb8f43c8a6e" },
                { "te", "2c11815f15a9d12af03cc64aff6a06e7e319896cec1cc22975a137770d8000d72cdcbfec04e1c1a2d02f6243f4cdeb5e70393a2c655643be7a75b2c8da123baf" },
                { "tg", "a85aecbc1db82c23fd5766ada4bfe1e6103eed68f88a7d9d405d476373210c50cfcc35a965644b2b4e2748e26b7e354167af74759a46b314d1bba640094d2ef0" },
                { "th", "7a057fc6ba2ace41891255af70a53d55243ec3b27754ec0f9d6b8bbd7802fa5a5d2495181e8a61993db04fa5063a34e73daa577861d44a0b0489c9d7ccb0d305" },
                { "tl", "1d3f122ff9b9b3dc4cdc8c50d421e038a3f0477326c75480f32e057bda5694624dd6307e5548cb91ec50b661032a9a1b999b679ceb879945ad1e8196a14c3582" },
                { "tr", "fb32da53d1f3eb301343c64283f852ef63e57d3be4d36bf42de88366a81f347d3f6e5f3468f348eaea85d46a210aaaa8bef916bb0b982e59f6e69cbd37971dff" },
                { "trs", "5f12a4f55bd3f7229a1ca199e6c96995c96303a0c786d6611b1c13c489728715cfec9ed6e236a2bb689c9e485a8bde71df3ca87e4de6866dc094bf71695e6ec4" },
                { "uk", "661d0c05c9e54b606d06bf443dd4e49c3a1b17a4039b9647a33623da00cd3bcc6593de9b897d220fb351396f2ba973796a2ddaba2f5cf93084325ac5a7942888" },
                { "ur", "b1d1c853ddcd1f512ad0309df81bbc8e8382c654183ed0d9c62750b2287bb0e53fabe4051502926cd35bb6b9ef94466ab6d2fbf8ecf064169e6738fa31f5d78a" },
                { "uz", "ec425378aef0f3a94763f3dd6109c47ba7a158b7b80a46dba71250ee052c846b05269518de017d7f021849e3f478b5631e42673ca8c73e5a4a75ffe971669cdc" },
                { "vi", "93d850bc76542e1b5a1d74b91845a8a248e6c0b0079a46aa8715d1e64ae940edbdf29b2135162e998bcb6e8614c3b6369289fc5259856af6b0e28d24f54e9a6b" },
                { "xh", "1695937b16f39aa48615fc00a1592cfe8e66ee9b804b34535f7cadbd6fdcb592360cced678d018ddf8b40531680250f1653854c82fe59a2b9b02181dc6ab54c6" },
                { "zh-CN", "fe4d8c83a3278ba1597df0ee62b384c6ac141aceabed3bb77ec63da789e0ab156990f50ccdeb72d98a278ff40475da7dc6902c6ef9279ec4a4277b49144deb10" },
                { "zh-TW", "f1107f5e1d1193310b4effbc21b8b5dd4ccafcf3092fee11ff91f4af933a25130fd1300aef79bcd22ec0a5f4bfcb70f22213e1fa1bafeffc3859dbe3d5373d68" }
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
            const string knownVersion = "134.0.1";
            var signature = new Signature(publisherX509, certificateExpiration);
            return new AvailableSoftware("Mozilla Firefox (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox ([0-9]+\\.[0-9](\\.[0-9])? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win32/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64-bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/firefox/releases/" + knownVersion + "/win64/" + languageCode + "/Firefox%20Setup%20" + knownVersion + ".exe",
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
            return ["firefox", "firefox-" + languageCode.ToLower()];
        }


        /// <summary>
        /// Tries to find the newest version number of Firefox.
        /// </summary>
        /// <returns>Returns a string containing the newest version number on success.
        /// Returns null, if an error occurred.</returns>
        public string determineNewestVersion()
        {
            string url = "https://download.mozilla.org/?product=firefox-latest&os=win&lang=" + languageCode;
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
                client = null;
                var reVersion = new Regex("[0-9]{2,3}\\.[0-9](\\.[0-9])?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;

                return currentVersion;
            }
            catch (Exception ex)
            {
                logger.Warn("Error while looking for newer Firefox version: " + ex.Message);
                return null;
            }
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
             * https://ftp.mozilla.org/pub/firefox/releases/51.0.1/SHA512SUMS
             * Common lines look like
             * "02324d3a...9e53  win64/en-GB/Firefox Setup 51.0.1.exe"
             */

            string url = "https://ftp.mozilla.org/pub/firefox/releases/" + newerVersion + "/SHA512SUMS";
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
                logger.Warn("Exception occurred while checking for newer version of Firefox: " + ex.Message);
                return null;
            }

            // look for line with the correct language code and version for 32-bit
            var reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64-bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // checksum is the first 128 characters of the match
            return [matchChecksum32Bit.Value[..128], matchChecksum64Bit.Value[..128]];
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
            logger.Info("Searching for newer version of Firefox...");
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
                // failure occurred
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
        /// language code for the Firefox ESR version
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
