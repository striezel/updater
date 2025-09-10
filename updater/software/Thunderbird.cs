/*
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
        private const string knownVersion = "140.2.1";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.2.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "960c554b070ea95a96ccfb8d60f77055d680de15a267c9542804166c34207523edd3e47e4be307d653b064cf4335fdf9861dd9e2250d1fc6d1044dd741a5e95e" },
                { "ar", "5678de47678c85f877f1e1a6330da20bed2d5c0764f44760bc750128f0d134cf3dbfcccef163d5b26cd5ddd18e866f16fb9f815e232326f67f1b74e1eb073a02" },
                { "ast", "2cd5ac2c84dc83f4c17452500c47bf64c7e7073b4acba42e154aae4ba988bcceac6534bf69efab3034c3cb04025a6da44f39ead66502174a250e1841846025a6" },
                { "be", "1b72b19eab06ebeb0f9bbc0b3bcfb8d2b309f512c392852c2645d29c7e9065dc62d96f03481ff11a54988e88d558493329cbbd6b19a3a5b3f8b437244434e0f5" },
                { "bg", "c68d4dda7199bf484c5b4ef22d90a0c74ff645c731ea44b7da7d713bf26ab1649082fbaf0a8e24600be4df5344229b86969e1e3035a80ef507858efb7b881c29" },
                { "br", "2b50cc56ff27fef24caea19aeb3e9ecc30cc85d1976a29f2ab586a7014562ee9befc034149de5bce5dfadce924a222eb2884bd9dae6ef3e163ceb920f3726ad6" },
                { "ca", "ec7d95597356aa7c0c436ae9ba836d5cd29d3bb055249f45a6c954a6b507adc25fbc8143e83198b329f5f0d76ea81fc6e7d1b347b97024a4887052735267fbc6" },
                { "cak", "fdad63950b38c531fa98982ee41ff5a419ef5a006bf375914e763874c0712a5d3e6fd6eeacafbe37bd9335a327d0df184d6db1216b2576ca0a59b5c0e45d61d9" },
                { "cs", "2d8b0f6b0be48636d510d4ec2b73c687c3f217a75eb95ed12cd6752f24b7519cce47acde5894d1f290b11f9b16f335e878400c11ae96f4b7830f964968398c20" },
                { "cy", "804b00b2964b70813613f5e749432047404b8b019c8a1d4a9b10a7e8569d489938b227dcc11d8162690cb880cc3e564ce13b21a13bcd37cec4dd96abcbe5361b" },
                { "da", "c77437c52e6da228c30fcc387614bcac8a3e00db0c4537bfcc2654c3aa945321cbe56a243bf9f84e60569d56e4e186765fb27c4dab14ce489c0e2e143752a2e1" },
                { "de", "db1b798cbea41d07ad2a778f28544ac24dc395a6295c92924c1aae730cd24a9d71d7f7a59ac95b12ab93e40e8de78479d83b291622de7df305407bf34b572a99" },
                { "dsb", "ded1c73714ee586897456db0d9b91b518c808c2e5539dac1c59e595f3d02f4cdc4aba12a809679040be41a006050eb4e8841662f3a3e84c3efa9115472b35713" },
                { "el", "7fe66a4a20a52cb226577db38efb124fba7440409188dc513bd7b7961ddeff57ed3f0aebd79fa792fff32e91bdec4389550a6cf0dbffb2e30ce0d83f8eec274f" },
                { "en-CA", "dadb86f8475285ba61313eff614f13bc6320e54afd13f8d8d9577956ab0a312e2c772f1269742354efe8696c5cde34762246b080231ad091c03f88b561d9926b" },
                { "en-GB", "83992995097d0f3a4152769069ef985408c0899ab0720d1bb8c73d5e8b3fdf1d2d1f34b8d687693bd060501b95bf772ffe3b4ca66705bddc06cd02ee2b6dfd08" },
                { "en-US", "30b4e426281218ce4786943d0fd6771824bf6ae020dcc41e2841f51387e1c4e56c099d0113ec48cc5f9724ffe1048c7cf75350412fc0f61aa8b4de0845f9b885" },
                { "es-AR", "4071843202827518bd7760490faaf61e4659eeb6f681a77cd1fcfa33d55fe602e08ba60d71d0b3cbc52958fbd2b0233dd2b45f5afd78ec3e6053ab5ff3546a6d" },
                { "es-ES", "20246fc84e01a0898c8954a9193a829d00f10c5b48a09fdf61a79eca17970f9a6fdab696e551ebcbb86c5a9021575237e24c2eb244df5294f21828a66a4cef5c" },
                { "es-MX", "c19457871fd4c9aab95b2f535f96be0e9fad38be11b8f1a0688d6042138e3289dc7e849c93e145b2684c9287ad843114a87a330a6cf4524ae07ab9b099da206b" },
                { "et", "94ad8c4f00a4e700767eb34d778cbc09946980123f245cb95c57551a5846ac8652d8ea83c7542680d10433f21615f63a7204254629d2b39d55169ff6272e6f6b" },
                { "eu", "9928920dd53a835b0c2b0440c211db61db81caf6969ce79c791fd8dc4e3dbbe323aa71d76964489355741e226608a37a40bcb9a9c75d0a7711a06704a794cb71" },
                { "fi", "be233221cab4f2fea3bbbc334f1ae9c2b1aec6ff6ab69491bea4fb062a1f6c815f420991bae7b882b00979f42f69bf8ea36d0068fe473a84f83284d85842a21d" },
                { "fr", "270e05c0144d5292cf782b1910043d7a7c607f5ba639c2819a3005f98eaab357b1603a857a657575487b6f7913174387432170ca5ea9e2704efae9f6f6c3c18c" },
                { "fy-NL", "de29dde150fe49dd21cb2c26b1a82bd2afa99faf3ff2bed6503e0d575f36aa3141455f0ab61b02bef86f6a8bb887cfc339aa98df3e4263bf304ac5a80e796322" },
                { "ga-IE", "b6d9d34738b6c9a80d4b9c5355a70ccafbbc7d8102fd396dd13a0f89c57e2416d433897d016479a58743a57766c4162495ad8dade2b1291791059e4d6ad96f2f" },
                { "gd", "b81161f6b4f04565185775cbb84717c9061c920eb4ef02549241a2e61427e39bb0496bb99fa7dfc1cee239d3f348dcab103e3d6a201bb847a211bbf3af203114" },
                { "gl", "cbd49e5848f8be9b824a6f9473c90719bf9dc2acf3b5aa779641c9f920f4ae12f496b697ffed7fea058d4f390257df6794ec61d322c0a485dd7e94c9f353263b" },
                { "he", "c1532f7fa7dee31054d678a94424e8e942ffe9388e352bba64b9de5756f0b923873ce54790d6ca06468f828d63fb313c42a50281b7cd52343f91eb42c5b7893d" },
                { "hr", "1254ff0396ab6f80b0708d6572d727cb8e51b8948b523002d6d40cdd599f389b304f701b21fd9ab56d068729d8cebe5a821c26471ddec24c531ee25ae928838e" },
                { "hsb", "e21adeb5a4b321d52ed72caee21272a0feeb4601bc9034920fd301a26f10d7979afc0590f3af5b7bf1ad5425a9418577887f3416bc009816b0679bfa9895fd7c" },
                { "hu", "85b40f9a7304342f1b12672e9290d6500da3173cf4b9da444c9bc3f0cedc54b167b5f896d0c768c1932e8038249e6265ed77b4f4db5d8bf03cecb0c18bec9a3f" },
                { "hy-AM", "76a8c3540a707144edbea690642f59760e7de24a800c6fd8148c087b53fa20d59c725d93246a17b7457d70bd7aa3699b692199b587675cc0b37b39c92aa56d2f" },
                { "id", "55bc6e90d7ac71c7c395bc3ea4fadfda18316f2ed753ee0b8e6426671002cbbbba5235f14c18902cd77954b69dfc7f077174f292c34712b60956902f50a2d508" },
                { "is", "7f1625af384ce1131987cddb320895867d8f85c1776e62f455117641e889cefdbb9378c7ff0829a534caae0f0386ee498cff4954ce574e4f109ec135faf756b8" },
                { "it", "98469738252b24654190bdd3e65a15390ba3dd14f5395c864af3218eda8a835f6fd5456d2330debcc77499371f4cc92ab628d23d46b1e9214435c0365b1ffb92" },
                { "ja", "4a43c02d01bdb43e74c5eec125bb29bf071c610b83e8dd4b21369c3a465bead22d1a94fc7d5c284c8fb2e546ce700031fa424ec275b6b76d73080b59ac330ae9" },
                { "ka", "e3ab06202c0d18ce55b8c8ed98c0cc447533d7d709d77c1d6b30ceb8b935eb15fe3616c4072e8654169c21197c771764a39274f072ec01870fb85b33df5ae594" },
                { "kab", "85489ea9916c70f8d20f71d02a87660bd7d0df04a9449cc434e2deb23161bbdfae233610c7a05553b73703592d730bbddf52cc4a9a7a72f9a0c6c70d7448e362" },
                { "kk", "5c3d20a5bef78cda6907e0b883000d4245ec9abd61c374a1676c214679461c029930a8cc4d5357bb6644936e185d967bf07c2a58cc669ce827561415d766da92" },
                { "ko", "1055276e2a5afc69e877c48585c8997a08953216fcd153efff5350185d03be6b2791badb42160a5c91cb04331f1fd0b8e5494e0746002da65c8fb38081b2e200" },
                { "lt", "c3cbc66fe4b749c301a25ff391a4a2c292c2f44944d11865f97e1b88f8030b2de0560b1c52bc5f88df508307c27798bdc747ad095526e24ec413349524476812" },
                { "lv", "a9c66af2c914ed2ab16fc29e7e2e48ed44312d941b193eb88a70555daea90e346eda76a8e800d97ea2ac5aad087031186bdf0c6e013fba4558c71372f693ce3d" },
                { "ms", "d74b73000c61df47f44d18fca90c665fbb6b768e17d40a4ba5f01bb58f6abbf0c4dde3d13486968c564a5f27639cc9cf8e5b55e4f1868ba0b71cf4147f0fb67b" },
                { "nb-NO", "d1783d46dc28b5543971253e63ae815b1a3615f9324930e0ad2d2a6cd02473b6c1b210d7ac22f2bde69164436867e8bb26fc641113b36ff1591747317e2a3089" },
                { "nl", "fcd720ef2451958983a618392b179c24534cb27ab66c6b4e1d82702b624d0acef952ff1c5830f4f7131190cb15e17d934249e26ab76547f3a8e52d3a5037b49e" },
                { "nn-NO", "67ebbd66d8af0ce5819952456b244c72ed04dd92597e547e8b01d6c0455f1b1fef3513e2bc25e44d7181a13ac3a8780ab465086e05d38a93d52e98bb2434a035" },
                { "pa-IN", "10033ea8a6cd37d1e6e83f9dc9d201517b48bff61d1411a63269fe4ae13321930d0dcb84e2e2f0ba9da74918b0f015cbf459624d9f31f4b452491bc7f1176b5d" },
                { "pl", "5d0a224423521b14a18708cac960841b4f7070cbb21cc79e9720bda380db933d55a80564a8d8cbc64713e456911cbd2963a6fb22b6dfbbfd021abf9d9fc2055e" },
                { "pt-BR", "a70bdf642836d00f9d328aa6bde51568d8d8b38ce0a8473f7aacf374a6d4c52e14456f0b78f4cc4f2e5c54ae4d5d13b58416f07aba8cd5f8c319754cff4a5c11" },
                { "pt-PT", "dad09ab7c9b4181a4419a43cdd0af8351382a6e12e735d6750d590150599d6069b7635f2880441e23a68b8cc0a4a0be6918bcaa0de0bdc4b33125909d440dfdf" },
                { "rm", "b246384f58ef9fcef57c3fedd78b42c7aea1d9bb76c8c32b596cab87993699fb244ef0d13ea80ec6b34fdcebc522a3132e1fca373c79abc505757380c4f89dce" },
                { "ro", "27662ea79f7063dafca058dcd414f5b94f4deeabd5a76fd0f1003bb87914acaa4d0f0c1cd7437f7393d8fffcb94e9ba4dbc6169e2bbacaee77588f17485f9304" },
                { "ru", "bdf80a43ba361123926a1aa04c3a76618d4473c7b4445e0e36c2cb36544c75083494ccb2ca7e1cbc62102db49fb4da9279b1d3cb1a11885fdfedef2f64754205" },
                { "sk", "7ee1fc321b3ffdfd70785c015668fdba5871ba612cf7aa548594b631fea3876f3260690f98751299ad95a57e0f2688ad209d82c271a78591ee1d9e069489df5c" },
                { "sl", "6fbb26f1727d27b861770fd20d792762f8bb0c1725de4a3133a03ca131de5a961d767aa74ca7a9b48bdd0b4481504b8399c8db45e59e08a22e3d3d83d6b0852b" },
                { "sq", "72fe9da1dec72efb6bf2e0be09b32e613f3143e593b5b627cfbbe8a4c6dd803ec73c67d7a03a62c1174c1857d4b531098013b1834dd95bed266546d5516a3281" },
                { "sr", "5c8f7cdd18cb03d7cf7079d91449a6753f9db1ffc93ef13ebdc2d1fc3c308e8ab521ea5e79ea546bc8b204cfb13f8edbd1bf4671647f5d0cbc7f42da075eba9e" },
                { "sv-SE", "43f96df5d0aabd98345df66f5493bec115d877f33de00ff09cf85a920ac456714e83f9cdab47d1d1c97f4b12d1a2661bbd46004570c52b1a0673d7bde8f411f1" },
                { "th", "a71b345c662c916e27ace8c5b72398eb9d43ff149ab9da2febb1240107fe463b888267cdfcba577e272bd658261d94cdd3b00ccb0bc9ee10a52873a328ebf314" },
                { "tr", "911026742b2d1e13927bfedaf864538ccae9e1476b05a61cadc64d0f369638c39e6c2686845702d74d1adc317108be8a47db5620b8907726ace499128b56dfe8" },
                { "uk", "1ff2e01b957cca9b2d6cd9377e360a17123e60ffd275bdfcf29504d15917a7bff54d7285439ea0f4ed21a948cc38522be8f03902e726873a2a7051a13204841f" },
                { "uz", "57c8bbf57992c1bcb6cad02e059535ad8702b5238ae6e719d44900e1f98e0dfa3781bb4dc4bd0ad4a5407a08dd86740f0bd913884ab31932b51595ad1aaf2c1b" },
                { "vi", "7a1384f3bb90624bf9961c37eb520a312d0bfe228f41be44f5c422a8d2eb498caba8bf51a855a83baed571cbdb8fa49ced2cbdddc4952b679abe480d4be5f80f" },
                { "zh-CN", "f3660c2bbb62c20cd5ea7853fa2bac747496754eab59ae28d9a0d1f0ac1522ff5fce6327f8ebf362db691385f816517a41b106a08e8fbe88951a1636e9d29cc3" },
                { "zh-TW", "3f055e51fe68a0370649bc4ff0157bc5baa69989e4f37b876c5f309afbee4e9d25deab0c8f1e1bdcbf8af64c33bf427e31d774a8164fdbcce3a003657326eca1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.2.1esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "a4ade7c198b9c86957fc5db1af4df1e66ecfbd287bc337d8b218a457197831d5b895a7dc0666c3157ebe35e26ea69c8238f59e0a76bb8438e0883bc9f34fa282" },
                { "ar", "ff0b225c1fd25560e214aecd25694df5561064158c60f2020399430b7bcfdd407894b6e1e86bc384a4d743c86eaa5e1d76655a1d6e017c925707bb9a5353f1f5" },
                { "ast", "1377b23a81651cbfda86244e217e72b9f3a534265e8e13946a24694a115740cde3bddb93a3116fd612507892b82dcc5232b88e5db4a86d2e5201554501dc1e74" },
                { "be", "55751a65af6f76d5f15522da25e85246aae407d5b13aca4671e5f81795e092f42a21cadd58513fa413fd14bfb3effe000fa1f633228478578c714ae3ca184461" },
                { "bg", "e8e8e4870151c3134a889c8aa795de84e5b809df15d9800c9152b2d6b34e6180b27ecf123defab0b73d9dcea1848f6bf00c5e8846de9eaded151eaed10cb16be" },
                { "br", "5a40323465f937aa2b3913d7a40235b8eef9818ed93d8eb847d07a0382ec54a2ad8adf6953f27d089c6a739425676cabb5b5d0b5a5af7b31eeae5643fced13ce" },
                { "ca", "1dfbadb34f1affc9561464632f3074781d134df8b7e749714834d29a46cb838cb2c9de2519acbb6018e344a5935e917bfd84b3bbd999094ab28c44f45dd81f38" },
                { "cak", "58caf8cccff371bb3c613735da7ca2e56f87f0f880cd4bfabd98f57ed7c4b8ed064c61b1141a4cdac8906ad9ff08d6625f0065eeca65a859dc00a0c8c9279f18" },
                { "cs", "4ce597177d218aede7b020f06704cb3856f9635366b29a269f4eb7adc5168b39e3724c5d9d4a4b863633308406a23641c13213f354492f74c251648633b8fb7f" },
                { "cy", "a5adc0c011fc354c76a8ed9943e7ce6d7751469680a035459bd684ab202e0464213fac7ce167fc84f023d23ee1288c89f5b61f3421b47f29ba2cce4aec9da3a1" },
                { "da", "9bb8b45f566e96dd14b6d1d4ddae18f9a35c509c17db8e48d9d542811934d94e704477ce15e88c66be475fcdab4ba7fc43a67568019818b2080c067bc5a67c71" },
                { "de", "843c5a0064bcdd8fc115c64780c05ccb6a036bf79590bc7ba243db47e57e3b613bd2d78e814c18f64f5fa4c2c0fe30e04bbe3b1716868735a2bedec1c92b4716" },
                { "dsb", "21a81ad59eae05ead63b6e694d3a5939d2a41927f053c5e4d9929d711eb2e571a6b6a6d3d01a361076e43aa6467081383072972577c55ef72a7d463647541ad0" },
                { "el", "a2c86e75ddd31cba40c7817c00adfd3b938cef5c2e0f4080f2ca2b640f92d0f5bab608f112fb388421e7e214ffc2e6d72c6ccbb6e7c8372ca6df61019449cb10" },
                { "en-CA", "15e57d1e123f2ce2ab5cae51beddc22529f2463801d25ae54d555ceb6f1c710822960bbda2770f491a073c7f1d1c36f7ff613cf2739950af420d5107d3f0a7e7" },
                { "en-GB", "563b718267cf2dd60870cec2e8c4f01aacfbdf8cec4dba8c2f568f3496c814c3e5135e4c7d57175b12e2d9fcbbd3b4578e68e0e98d047667542e7d4057c7aaff" },
                { "en-US", "aa7484ef2eacfaae66a1b8abb02951fc776b65803872f7391f2fbd1a876dd0b34b4f54a90c47b6869325729ebbe2e6b49ef0b194b47975b39a7c0f70250ce223" },
                { "es-AR", "11b7ac408b1be691d873c24341505b73f7665032fe44cd99d0893281d4a4ad4cb73d6b7c2917a140b8ffc7338b9fc0211f5383041000abae83c73cf9cf4cba87" },
                { "es-ES", "8081f3ea7047f16b497225c5728ecc03140aa85e04c7a8c9609c5fabbcbde4da34419a2eaec8885fbc25047c165e9cc5dcd00c0a410010df5793ad4eefcf2722" },
                { "es-MX", "3fa2ed53d453b36261c7f1d4975650dfb0f3a1199214f355432a528fc5e4f7abe0727e79d558ed60b0e67aed1801e42d3aa874727534a1fb168b7d7ce91f8405" },
                { "et", "179787512fbc65f4a034645c59a2b98383cb0e516ad421adea536e639a3c03f1d1424cc89d1e279ac7d402861e3c715127ea4a87c0eb040cdacdc47e289edc4b" },
                { "eu", "242532756dbd9fad4a1d5348c52537b445fc4a0b0284aa4e0722ee4c02cb9628652e231e8b3311e4383121fee7cbe9327b11f01442ca10e44db17ed1f72c1eba" },
                { "fi", "b2222e6caeacea031f59e11b3615170bbf5d745f7538fea3793934e34ada7b2470e4b429a66da68df82e63d0689d31e33b98b592d869615ecb7684962d9cb5eb" },
                { "fr", "b1e18b2145bd1912b865eb8b631d492588c1d6fe75627aaf7de9c0d09bedef45879cdc2b878db5fdaf06087480cfccd726289d735097225b875bc4e3e139dbbb" },
                { "fy-NL", "00a52d59cc4d523b25fa1f6d2688f21ecc422a6641e1d88d6b6fffb7677ec2e3fa6ac2702ae449d968ee7eb8f2fe24c57cfe2e0e2a5a052603928192b3eedbc7" },
                { "ga-IE", "d46598106d4e29e497bf45328f68db5c4095d80ed1f8f5896c7354d788d3e7ae7c008e59ac8d9b44d24a47436823b44883c5ed68b1853cfd0322e8c1f7ef24de" },
                { "gd", "993b48b3910bbb876355b4f02130ae3a271a1a759293c3bfc996fea662955111e685c57980589b06e398cbb80dbeaa842e309e08435fb1b4c25f2790255c31ed" },
                { "gl", "d5b9207f64b8509c1e3e0b2a6acad58be225aec1a51ef351ad7e177ad6ca29cf0bab37f3356d0b96c05ae19fb81f53acb8e6a67fc2b6612aaa3e1db5871b227e" },
                { "he", "a6573be7c169d364e584d143e422c9e190629169459bd7a57a99a783410a050635e110065cb8f8dc3037911c184d2f5e6d10dda72c8f3950959cf6efd8515d88" },
                { "hr", "1c5cc978d6081083559be0f30c5c652ea2f2c3f7ebf1240276f4626f60af5028660295c033c38ab79fcd0db9d53f2237a3687388ae30ed02900c5afe537ddac9" },
                { "hsb", "cb5ab97c1d85155b9505a379d3bc452b2b2e076ea311bf4e39d13ecada38bcebb06357d1ef71a13a757cb305d954ffbc7229d159bbdafa1e6cbdccadcff345d5" },
                { "hu", "fb26111769c3dff2238ba2eac6f79a0a8655a933d08eb9a77988a5cbedf69b5bc150ad7b5d64ebdb47d814e1a25920f740979135b276f58bc93c6c552b811f28" },
                { "hy-AM", "348b2616afd556531bc39c2b993c60f96e6bd9840a6089209165c8873962a6d22cc4ed38b5686ae11c5676f2e1c3bf792da97bf01e374d29f59ee09802654b4b" },
                { "id", "41d3ecd8b9f19167ffd88d69bbe8d40ea4c68b0bd88589139d65e6c971a6074934e0ef42bd66282ae8fe3efe311dc0e8ac78d42b9d034f190bd0a0351ef1b885" },
                { "is", "6c7d58af9b79111273d909b84bfad1da89aa691de5212f1993e8bde7105e08e38f1b0ec5d441cfbcba55e479f43025a9b49979495eb3e9587c74a0781de79327" },
                { "it", "f46b4065586195a0fcc7f5477a2008fa10182cec0b0c2829da71288b6cba2c21ed236e1444ea9da0aceb4138ab5a05ecd12b3a6141bdb9792971d13a0936ee1f" },
                { "ja", "4ee26e0e51578e5fb266655a44a5954663126e4ee418a50dafda8de966ec4600341e8d4854cd87d644329935727bc84d92df99d7ca6042ba67ad6130001c0628" },
                { "ka", "c097dc93a5195a205635268b98f564098359fafca81bba048007aa32d2965237edf491a5fbf40aa222446ec3bee51eecfa8dda93bd73d11bfe442b2e0e207589" },
                { "kab", "e7e3edd8b34998231259d8f17ee480e9d0d51d07e1434b2962a604606e0a2475f374c4ef41f0c7b7a85505d4ca44de176d6ba2d5664d3001a96dabca052bc2b6" },
                { "kk", "efd41db13e98d27dd3c063f503ae67bcdfd96870248fd02105d9869112d14cf84478f0601050a2b90c72c78a02904a61c539b0013ee713a0b651bb8a90d1974d" },
                { "ko", "0409d71dcf2fd041c9eac62693b7837a046fa5fca6a858359c365a425dcce24862e670879d4fbba70b0873c58ba72d799af18300d758d9796e559c1c060f3ea3" },
                { "lt", "6bbf1e106ae8d9c55742792ee6177577c76d04a9b276bf85c12d439d0de9029f58151b3308548db5ce9b26bef58a543f7f40789c4e97c58f743586f84b6dad8f" },
                { "lv", "0de862f339d675d1141a7aa8c4596aeb0b207d558e290430b7e4a8ceeb2772422524a1bb0caa81b375338526275216299afd10d2778e45974656e76a8b54c856" },
                { "ms", "490a4b0daeb4d67da0b1c78bac5222dab7fd38e1880ba80a3d593ffa482fa5ec766a2918e86bef7f73604ccda16896466b87b42ded7ca937cc6de26eebd1c62d" },
                { "nb-NO", "277c89adacbeeb1aafecfe7cc13041e5ab75d3ea21382710dd76662ee988dcf1a66385de2c063e0cbf3b93afd588f6df1cdc0c7c3d7d4063ad853fe59c4d9058" },
                { "nl", "608be9d8e3156f310da6b06e3715fa7e3748b0e7b12aad6cf72a2f23aec22bdab01dd42ee86ff67749b93d44352b7dde2fdb5e2b81440b24cb881b7dac9f2f9f" },
                { "nn-NO", "00e2ad3927a676af2cc733511f8e17c124540fe98b3e305c6d8c0695a19640de9095096ba4b6d38cf8b6276330d1b67222a42db26962c708e296048b585f1c7c" },
                { "pa-IN", "a14411ca3a66d5f8f152b9b3f511eb4e5f96228e849c7f5c4a57baf586574b70ea26e12f59cf9051ccbc38b4606e88ae157c945a084637c12f1831e0dcabd871" },
                { "pl", "73a71513cb14824a5ce564a997f77b0040636f9494ec35820759d4614e287e657c2089cf1e1e18f5156b3b12f55e858685db7189c3e940e39fcf5f0517e6eff2" },
                { "pt-BR", "fcc2f1639c1c3be7474649ddcae2793f13c909e0fcd8b7254028b695ff2b365bbf8e512c3c9016b2917cadbf1ad53ef5aeacb6f1ff50a3a2f7738e0849546b9d" },
                { "pt-PT", "08fecafff6c4656aefa27a6c50a668e9c4b9cb7c3643d650d297a4cf4aca94b7f9d0a80024e050f8a68c5e493d7ff55d5164228ba6fa8b7929c03fd73050bc00" },
                { "rm", "6fab15402f65515637641d6fb43dfc4465fda46c8e315cefa18e7ab9ba3e043df2cc433ab125134e103c121b8f10a1bc27e38c78da67eaeb24d82c6b8970888b" },
                { "ro", "6674e24ad62feaea93f9cbaed5a6ea9f520b2eeebe224101a460ce96c95903488b88123367fee2e6af91c770fb01122a48558500e2c0680d395503fb1f5e3754" },
                { "ru", "2e2cef9ed6b420e926d2074a35dd50ab2d52957e8c9ac8893d6f3f8ba53230001d925047f77a003b35fcc0b6cb2669c81d98146738e44cc957a97f805645686a" },
                { "sk", "b107a4d075061fa3b335047436190bca006199baa840f6807aa986cffbff92572188a935d69b3b0f5c6b314de2159f4ecf62b1ad0188dc6c1ac1e429c18c736b" },
                { "sl", "cae64b71eed1b2275cf909b73398ca04cad50a9cfff264699d6d9bbe59562d151c637ce44b8dbcf42f33da4d8c3ee7b2aabc318ce4e64d7c59830ae090757ca4" },
                { "sq", "76d4215e580ee9b9a5bf6b9aeeab8a4d48f8c7219d213ed4acf1c565eb1f88ef9254bf3b558a2989bfa9c7dd2c9b43e4348ab9365b7c28583f2ff5f9d1f5ff5b" },
                { "sr", "c0b9cc3e91616b8fdcf404463fb396a0c3f837dadc6c54f81c0f79ad32e919a2c6934ede852fa8eb76d9e0070e31406185e5ace7edae551d635648b407ee0078" },
                { "sv-SE", "9ed82b766ba495aed7ac9a43a0f534e272b3e3c4e927842df574f88f4373b70f026a1b0d8a2aa827f67dadb433d3eee19233c0f10608b909345ca377cf6e74f5" },
                { "th", "c5e4271dd6240a16fb502d13da5b06d9570ac67a1d6cef13cadf4a7038f544f9dfbbae538e379ffeab34a6e0d9b80d1b3b9db09762ca70fdec290246a71e36dd" },
                { "tr", "20df9be99e13acdc3138436f8205c0537d67bf7b92678b4b455f48ded2b5483f1a6a90ab40393e5e4a8985b1f2c3561111779d3d7d7424859e175cb189b81ac5" },
                { "uk", "9901e64886ec303fdc5d14ab5b75e055de63e2ef511fd1c4ec4a40f7acab258136aaade4aba181e8f40a052d01029a42f4b7d0cbb51f23f391d63e48dff5c78f" },
                { "uz", "032a517ae5888c62338326d86bde0a5e3853313310715b9e918439ae55d3fd21249aa29d4a8300efa4ee673f12c3055eec0e22053907b315971d40c2393bc3f2" },
                { "vi", "b80b2103f064aa8dfcd4bca297441ab8a2158180b76d5a8652a3e98d8391cfa7a81abcdbc086f8ce0e52fa179ba6f84ee17d1ff504223847960de2f00585af7b" },
                { "zh-CN", "4b0a80c7ad98dc6b893e293d43a7384e316244576c69597f6fa744381f9c2336f553a45e6ebc9dd9058169cb050609180b174f90fd931d143cec389a2f25aa86" },
                { "zh-TW", "4ceae8f893fab61a2c197a70507893bb1336ba1a52d476c031ad674a1670b710ff1f418054f2879b60fe4c937d43b4221bd3f90c927f024b20e930a4d9e38a4a" }
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
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
