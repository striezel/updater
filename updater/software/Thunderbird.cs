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
        private const string knownVersion = "128.1.1";


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
        /// Gets a dictionary with the known checksums for the 32-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.1.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "a6731c2874a88f4c080dcde0ec9d1bc137a9dfccfb9c87ecc7665af1c4c82d815261d5b24cb1df4c446075dd0ec07219264573e73de8810f72a48d5b874a3677" },
                { "ar", "aa78c745439203baa02c5f6ba8dfc3740cf81e44e16eeb0f1ffb1c99ee2eee3964c4979995f79a633db9b7caf28a398884a368b53721d53894777daea636ec44" },
                { "ast", "66870803e5dca3593cb11973646fbbf0653c349f22eaa943709ab8f84d17f454ba419f338cd00dbfa93e943d9a4a05e5b45e0fa40d39a2b3234f8c6c596fb82b" },
                { "be", "d222320ebf5624b5e5b4d439003af9df899891520e13bc2c416a54dd7a5f69424463203e1cdec2b46571e892d5cc58919e4768e776b93ec8eea995935cdf6449" },
                { "bg", "d2738ede4b416d99073e2bafcffcc660aa49f528d11b4bba1a6adcd79602abd39690a0c6937c4a2ee2f64c57f876b581ad232e2be68d945337ac1060fad60717" },
                { "br", "67ee2ecdc783be8b21585cb8a4b867232157d20716ed92d3ebf3443ca72f743dd3bf06c89dc9c2fda2794d90401d10dd4733269b785a36298004358a7b9a7a53" },
                { "ca", "b2f01ba91f5938aee01405ff5d00d8a6e5801709776b535cf8558cda56fb451e656f90f6379e810c1fef826e45205a10cd9c8d7ffed460bce11882634e331c94" },
                { "cak", "2c0165b0e5e24b345ce5026862738f7750893a5acf7bafad5c2bed2c3efc0b2a7cc8b32f0879b39b07fd8191e8e8f3eb56e850b6953e68380e86259f5a653689" },
                { "cs", "c6ba5f8ea60e5ddcf14f00c372869b9c9699499a9e6725eafb8acf87f57dcfe78ce5df3fbff7e873f5c057406b85a70a318c66ec9211bfdaffbd67cf0dd7c4f3" },
                { "cy", "f8d0ea5304512836f2dd797dc8958ed709f41e7de9f36cb41b602a5d3bf73aa852fbdd31119c450acb5836faa1133dca751c54b41f913fd48038d13853c6ce4f" },
                { "da", "8466981acee10ed3714a750935128d091069c7455bf0703523d972a906bf763d6efbbea1980750b7bde39e075796347baeeb823ead70750097b14733fc5d069c" },
                { "de", "5095582a336f3ed75989b7f1f9b744311bd6d2743f41fe6e2fc288168e2d1a265601d50844821dd7644e86aba5bf44bad61f5caafebc11cddd3a1af52a1c1ab2" },
                { "dsb", "a45a90f4f598fd0c26eb923868a9715e24f1346ae12142ea984f9772b26b74c0298e2d6bf0b822529c406496d3442bd6fdc32f9707092ad18cc9da433e3c6d19" },
                { "el", "22b4905e422f6145d143648d89a2968a6f1e0b52c8c7f3b2a422bd3817dda2b99f4524c656261a2536f1fd8a2eb176e6bedaa80c04f4179e37133f3bc71caa62" },
                { "en-CA", "b75c7d0cf40bf10374e4428dab01ca0d12ece41faf898ea86e0d00793bec29e42a7e09c5323066f9efd22367f550d850d649d766edd78400cd531df148cc7ec5" },
                { "en-GB", "370b5ecb4a7d8e3bd43dd28389d1995807569c9126b3259e9b7ae513661f88eb3aceaf66c97e9ea4f45670c44af6f719801f393a9bfb2e0aa2b886e8d4bdd41b" },
                { "en-US", "0063e3d06cb8f42dbb6ac3845e5f9faffa88d87613b87252bb64d5c920640a4346b29c21007f85eb25c3662894a77d960d7caf3d5f381744e4ccf72f8e159978" },
                { "es-AR", "48b1c1661146e47b12f5ce5d6a21faeee4226e5ba0de4478b84bb2cd2edd17f5d975acd9cbd86db7949bad9f8c38bdcbb26d68e6fd1b89a19aa7ecbd770ee917" },
                { "es-ES", "399c3ed16866fe816808f69deb00e0bc7239c06fad2147222a0d91dda2d4c990290abc75fbe2ab37edd2d142d64ee8e5b9c00345260e6fcb19b4230f98fc7dba" },
                { "es-MX", "d2577d2ff33cffe125fdc5e8d2112698f31a42563e96016550f46c4acf3f7e1db3a06999e85a6a931b3d807545e41a6953f3b072b900ac9615d4bcb2009a55ea" },
                { "et", "a09b8c0c58a791fa92e89305a0194dce607bcf21e4bf8cbbc4f43cea861da647e66813e10d6208789e415e995c16aecffc97ba9919d65955570aa408e183c39b" },
                { "eu", "96b137eda7ca475b8daf5e47fe122ef35b1c4324f664252d0b38e88cb5c1e7f59caa49062f51785b4d74d96efea77d0011aaf9e5a6cca7b5401a3ba3bfcdb985" },
                { "fi", "f98472a7d9a8dc9880bbe0b61bd298e14ccdd11dd614a571ee0261f5aac846c830bd0946ad1008be131ca6f207bc2dacd8df088e9bf7875342a4faf99003b4b8" },
                { "fr", "bf5bc720da42e2aba386a12ede59505913d76323a5daedfadb3b29fe89e9bb42971c3d116c6ca352d88961352b34e5028b96a5b2e73b2b73cb1d5c5f199f992f" },
                { "fy-NL", "0bb1f74a47b86b1e01bb9e7e83b457060a3b1024ba3c5dd36b1e058a1ae2f79001dcf06f5bde90a9b2a6b7204008df26783701298073f451750669c6e93c1cbe" },
                { "ga-IE", "04fcaf82b6994e5301854a6acec15bfd488880bd46d40d78962ccbdd2d10e7bf2b49d197e4514ec4fdb209b5877714fe7ebf62235373e297431b2fd4872bd557" },
                { "gd", "bfc9776ddc836a6705da87b38a40c3f5d57ff990506e399e07a13ae3f2839fc88730ac8b785dd5d6018e05f9136566bb539f3ad3d58dc9562af72b2d41083054" },
                { "gl", "ab4288d8f33366f2728779a742179181ff88f851a725f5b594cdbe292a9b2225077c0cda99878474761c657ebf51feea172099801e1da77cfe29c356c53e76ab" },
                { "he", "4db7550d8dc85617dcf6c60a90f60e89b971d64fff92448751919009c49c84704ccea917ac1fbf55e1370e464023254d489b5f604343ff5ebb535efce3deaf1b" },
                { "hr", "a8666187e496ed53662d6e2e6f02e0b764a07e4ef2830bc97e8321c0f0660f569b7ec1b1656f16ecbe5235e64ff001bd690d0224253a490a128073e9ad892e37" },
                { "hsb", "659343e0b8d5de008a89808ffea60ef2c76421789bcc353826b192c3bf0e29b39739d3b645e74935612bf83b9aeb292b45270c6c25e89e59d502de01ca897931" },
                { "hu", "941b01aea12018aeb418cb0d31d300961946faf364d3c078d317200fab5b709bdb848d9324bd7685a20bc043429b8d54ca74604b4037c238a02f2e7432973b9d" },
                { "hy-AM", "4eb38265cce5e9b304dd6f3e95ea22b9085bac4ac91624bb85bae209507ee7fefa67446e5e724ce12ce50cbff77ae73839feb540f73fe56bf50e975d38a83875" },
                { "id", "d5340da7ff3c1680bb59378a071db344cce3aa7322927d52f378a5916083062340649b0f9f27aeed092c236fe364895b941362424e6d957d23739cb90096ffba" },
                { "is", "682e3615a82d774ecf60abafa3a0c94bcfcd303b3a276d19cfb29477859e5bbb4ca1a8c29db79f27ae7d403a1fd6dffda137f8cb79a780eec9d9358cd0c9d534" },
                { "it", "1539d129adf17005ac03a0ceca8982e622e8175254e68ecabba576a9e91bfa8d3c0a59749b448d36f44880c99ab423d2fb9906f8b0b6e205e49a44e3d1448540" },
                { "ja", "405d82382f08c82fbeacd38ba7c311a50eb926c17aea4a822103a1722b59cf29faa4cc4520381fe93ca5add697c337e046e3464ad3bd9edea609beaeaf9322cd" },
                { "ka", "783bd571df15a15b51fd7b6a91d56ff6740f7254b0c9f3deb33b2598153cc8bce7419b9a743821f7c15705ae93aaec5d0f7e858252415dfa1d05c91b90d03837" },
                { "kab", "1b21bbb573fa04e06ae5cdc37028bf68666bcd6fb10bd612212df35b18fe794b4e68f59b8349ef7872a95429fd5b0e40edea35a74c32d867f44891f8355e7db9" },
                { "kk", "eba0f9505a2ebab6d47038b2c49157bc9e8b7fd8902ecf2252406c21f8d1c637e34e5a1be029f7e3894066db7c076f306481bfecebe0de7152f5369d44220cf0" },
                { "ko", "b3ee9bcd2d64dae656ddba014bbef481c0e8f05fb31b684a5a7791a6323ec6a40ab5e43e89dfe61f4d65bcc649467c5c9574d75bd0afd16b2b727e4e465b2d9c" },
                { "lt", "cf52483f1010177a98c69bbd3f187342b45c0e0e27d566d0afe10ea6bdc9c0afd66f1035409fb0eb795ede67d004662cae27af43ae223d84c059a8840ebd841b" },
                { "lv", "97d3e0064a75bec9badb2db2824b9b6382198067f49dc83a3351b1afa0f89c113ce2e65f268df5854aabf409669ec772561110427dd42f0c12253575044b6557" },
                { "ms", "0985f1c3785318af35105dcdef3b77d53d295942e79a4831e4af4cf5d57360d9544b9821cf3342b76006a2fcec258f455482a8992bd8d1aa511d13d9e1a8e460" },
                { "nb-NO", "f7505c2334ad2cddf14991af9adb458c59a6d8880f11eae844c32878f05c98633e9ae1cd449ac3f6cb4130970e378f26bf0a63051a26f0194566851b0fb109b5" },
                { "nl", "bd092c128701bb4b5fbef5664bcea151967e832d0139b1b967c30c9820a78b6085f8b1a6e9716fb383fa8f33583925c2fde80268b3f761185d9941763e33b425" },
                { "nn-NO", "2f1bc18f8a9b7cc4744b35c431ecda5e681be4790a293709e3f6a371cb6b2e24fc5fef97dda00ebee21092a808c9956d04e4dbaea11def55b1a5f7e898b2b6da" },
                { "pa-IN", "21a14d547edd08c6346f4baba86de6b67ad00acaf3cc7ef5d230cc89b1f123f09287af7548f8a6a749f7063c2fc7c848ae2613f64599b506f48bd767a2f64516" },
                { "pl", "00bcdd7c156603b4c5dadebc5ef5b949717e0929c93e45a1ab87024854388fe3747f54e1ce99a3f0de2b261d3c9470d203942c79fdff1875b18324cf896414fb" },
                { "pt-BR", "6c30c4c167a2e5b6545454a480e622e80e35006fd350b1f5bfad00dc6fb41a376bcc10b5e708a8ce0c7645f58b369485a179ca9583b01dc4b599d447a570ebfe" },
                { "pt-PT", "ad9c4df16b3605797e7cc2b31ff61a36be6acc7d0e54ec8a17c470b8be97e19dbc92ce7902002fc9c174e38ab549fc07ca70a15216bdce50e1c7863f2b344e47" },
                { "rm", "5df124c5a1102b0e69ea4c12653542e2208fd4b5066d6efee3d8d95e9d67597a451d16b8c51d355cf7ac677bdbfba451ccb3362abc7833fdeb8bcd2f0e89c7f1" },
                { "ro", "635b84ee75971fcebd9291d5ffb08959ad79c56eb80ebd3762a62fa25be394c25a3a24488546724a39a49c523bd2e838ad51cd551472833073cc6e7d4e79e614" },
                { "ru", "80e698b327596a6f8e9449195b876196b861cd56b937313aea52874ab7b8b9bcdc76d914452a29c461f4352dee3b70b58c29d9b30358ec9d51537b64e57427be" },
                { "sk", "9bb0385685ea0826f5361ea4a5d28b7b11a6f8a0dc9d4f852e02a0a958539f3dea6677d4cdf97398b3bf2be08b8ae98c098812499a4433c2af5db8fdfcf7f6e6" },
                { "sl", "dd73bd59ed166370fbc9c33bb21e4b7a834239ecc65cf6ee18f0f09c40a1f1f6606348bc3a8a1d66db99511604c981fc147b25055e3a7f967aff542bc925f282" },
                { "sq", "211f643419bd4f8e0624cfd5c3c4b3e7801afd29732ec6dfeac771fa07e1656c62e8b9ed832b52544146d04972e36467c8bdcf47bbfff1d26f8f9b93c90cfe8e" },
                { "sr", "75cdd0bdea4e5add0c235c23d1efd2d12d9ece7ac7becbdda84f1e01296de7894fd043682818bf9d80b3cb3c7a3a55bfcf6a1ef57af47b7012ea6ea9020d9f98" },
                { "sv-SE", "ba2fcb1fa6131774151e4148dcf03969728e1b9c63a2215fa43b39698e4fe6f3ab5473f1fe4efcd093b67b2e8c7d7250a6c643e5e46d83aadbee4caf0a4a9597" },
                { "th", "a88dcdb2cbf69fbd4b513d287befe4186fe7fb6e68b25bc801858990acd011abbc6219bb3b4bf576b24d8907392d7a61fb863df97185dbcd56221c6c781a78ba" },
                { "tr", "156f14146f3ba2556ed457dd5179bba02103c4d2f4ac28524c9c22241e204011fefef3f3c167b912197c7b9369daa40d1b11db8037f859820a2f1d8b8747d7ac" },
                { "uk", "44ef3cc986630b5f172316f6bf65df4e1846884d39ba289c019ac41fdb4eb762f82797ca5f6e216fe6df08e35e1ea4fdadef6f10190be01e407fc2979bd1e380" },
                { "uz", "1b30c840ec3ca3a5febc7340c43e8a34b6983f78e63218788823484a28fec3e7fcbaa3ca5eb5636934eb2e8e0c7f8d8130e06dd2ab6d530db952468bd5b28088" },
                { "vi", "31c99c6ab67348705cad2fdfa7918118233298a656ff78706c574429acf9c3c511b924ca888bfc35cc233222884c94653b8fb644cd1524355e3ecc204aa1c18a" },
                { "zh-CN", "2df6b3cb183e87aefcdb214ec58a51b22623d7c7c57f9ea260be5c2993e0110e0fa94e5dfc6e183c451b7bfe7e80eb93617ca58294653a283fc10317f57ca481" },
                { "zh-TW", "a53584999d56d1f6319f1798d567e909d2821c54bba9bd029e6ada8c95a56ed42f9ff8988c282b557dc6ebc62d4ec5d3fdfcc711539401a609a05b54a57bd0fd" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/128.1.1esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "d7437e4656afe2a3325f6c30a4a55f90b9806bfe94eb100555370432d260a00188c0e2ab7d562ac91ad3c63186bd789eb7598520f5fccf8e44602886225ca3c8" },
                { "ar", "2c447ec54579a761837a3013361eaa5d9e532005136d5b25bd7549b0f5ee7eb076ced482991256eca99740de361b542d2ce6592950df7cee0e57c1708f0dfe1a" },
                { "ast", "22e91b7d5aeff72812346b37bef270fd8940f6336a260721a2ab8dad0f9ef782d6ea09bc0ab1e5c803df56b20106c4b3937f3e30da7ca054ff8aaf89ef60f0a2" },
                { "be", "0cdddd7f6602de3554075ac323753b00c990245b772f4589652ff38a3c2384f4477f0e5c17340a7363843474f59ddd5f70e5f6ffdac0279f9bae0f52c9fc0754" },
                { "bg", "032118b9e295d871ef2cc5c9bfbd0cfdd748b65e144b54fb08c3e45af4c40859ace42aa371b593db461e1d307664d22786ac209018d87dacdbbd920fa266cd5d" },
                { "br", "ce85547e70a771e82474437d7cc96e19c9ba0da20fb22c803870e36a1593d2ebbd7053c94457a541b9f012517991155bcabb2ffadca8a2e0f94f82d54a8cd731" },
                { "ca", "811c2311adf2d5866cafce1457f87bdae35429b0cd0a2f7553c17da2da21fa47edf31de8166d34f080ef640e140cae7249c2a8cc53dbca19cab5896ad08093ed" },
                { "cak", "fa78aee913bbb3f052487c26b9a102377b16ccb42e8c1887f6dfdf860a9ce71bb1613e6ab0efa3f4b16eb05ab7f94378c7c3ee9b009a8f5393a2e93b0c8ddd61" },
                { "cs", "8d8a84bec9d5e693872b20ab2e269b61d4807d9527b92ca00a4ceb2497d6dc6719161c7ae1037187065699420b255bf5938823f49c174e7b3aa81ec7cf013e4f" },
                { "cy", "e8ca94c0205b537fd3b6f751c2be739a26b501b5989556c860ab961faa2cf6a2695f4404a94fdeff46ea8a3556433118582e006beba0a0c624800a9031eeae3d" },
                { "da", "5f03739da2a0f9092d6604e20fc6c873542c91bd1d94aad1ac9190784631b130e22c8450cffe49d6c499b4dc491e32b538345cd6fb818d2597ea2d9b1ab4aaf0" },
                { "de", "aa0548c33d52d44e7c351492d14b25b931b474164bc6b87f7f6164a2acfed2514f45585538d9a91656ec02dc806a65b7722d0b08cbec9edfe4b7d2c66b8438bf" },
                { "dsb", "a3311a31321115147fd69b42e4dba466dc1248d3651d838862d612942dad71863fb5146ddee0ffbc7544e833453255ab3df9cd2e9214f9eff36446bd187c1701" },
                { "el", "3452188daf1afd4ad151a5bdb5c605a750550ebc6acbb9c767f0e8ac961b292765349a2dff51a0c6b7c4a0efcfa6749a59a6189b9d8a718ad3f57359b97f7480" },
                { "en-CA", "ee7d52c99771585819f0b49cb3fc48155a7ed01b901d14140e50f5020ed4d291299ff2f42df1dd4463fa72644e176b8d9873990164c0893d2932170105a33a0f" },
                { "en-GB", "3a3e7ba3ea7e328310e69dd380ca63b58db9f0b33ba304ec7e21e7b219b2d1b4f669752a375b6e1f1fbe2edcb44af9529ad734f05b2f0529c04fcb97cba95a4e" },
                { "en-US", "e84a054dff25827334db7f9d719c2ab7dc0b7bd26e85cdb88c1c144755a2d632331fe70929b6e3386f4cf6cf0dc039ecd794646d1d7e63a2a46394508d1993b3" },
                { "es-AR", "3949205bd62a43839ef0ba160aaf5e9d431ca1bff76de603640ab0962df4dfa548a41e109c5766bec342d0b6fc988c372804edfe61060c36d348714487744dbb" },
                { "es-ES", "2f4208bc244a031de1a314da8bb0f0690e5a3eae5b686322a5450162a14671fc62479466ec0933cf180a0942ac53917a7c97707f591905416fa8d7a20e15c8ee" },
                { "es-MX", "86a3b8cb8c3addeb1e70717ef2c417b623e69c8fc9d9a3ce6e30a96e5a429c9577f4aaaa85ae7c9957f450c313646d2a2a1bb9a1a403d465e84be587e769f4de" },
                { "et", "af492fdda3695d148e33f91b9a66b970f5a9b9bf4103d9d6d7d8639a332fe4b498ab03457849dd1596577593c23df848da2bde9b726d651319e6fe7595800deb" },
                { "eu", "9226b877ec4cad572558f4204c924cbc1517155c33ba1afdc563732a8e175bb9f074142a3909174b0030e9b533cfaa5fe412fafbc1804a47abbcffe334375502" },
                { "fi", "7376d039354842ba5b8aab9fe56975167c39b75901233127d7ac1dcb91c7bff52d13fdaa8b2c77b690d428afc7469bcfb2f90e1615db554e42608230b0eff566" },
                { "fr", "9ecc946837b7c7422231173ec143fdf80a4c49f126acc0137be302879ed50a778dd7e125b88f68386d85b76152a0a3f016aaf5df852f93ec25a84d2c2057eee4" },
                { "fy-NL", "cfbd61bc78138e8266bac899a11f96437998cda16ed43b6970330aa1672ee7cdefa79a8c38d7844656a448879745a8398aa36fd06a620762d637913799301e19" },
                { "ga-IE", "0f278a57c8ec1932ba84677ba37c414eb2cfbb35a3ed90421ebef010a42cde5b29ac99ffe21fe203be2ca83a670d8ff77878e306347c35a83d0b5a9dda1aece0" },
                { "gd", "92152dc4b7fa3c057eded5881923161c559f57eab6842ebf45043417289b997ad2df597d61cb4dc512145cea94d82f231721c74d17718b696e8b211bfadfc016" },
                { "gl", "c62906a5b51fc4d0ede115f85d0ea495f458f06d1abe923a5a6c27e1f6c06797f5acf1dafa3c5ef816d65df75a02c461d918541a9616f9a0673fb1fce6d47af5" },
                { "he", "f4e14b9ab83962f81b1948114ce8000d0895b942a4b996b80fa528292ce8130e1034f87e126ca61df388ec22d745cfc235636514021ba089280933bc324a77f1" },
                { "hr", "b59c09191a7ebce52bca82588feda992a0baa624e88e9e77b4f5bf103de6e15fdda5c099cb7a8bc9d6244017163d07ceb89f557a27a32997266e4d6ed2a4136c" },
                { "hsb", "9d99f63b327c519a5fd9f3a8e4877785dbb331d97c1fe71ecb413cceea6009cf75b67109ebc9010b7fd583442abe25ab30debf89ab04d57e6f7ae4a11d127328" },
                { "hu", "894c9f6a370c2bb1f89a52216d8b51039fe7f011b380d89f21e1bcc35d6255ae04c53687d8ba196932eab9196a5d6bdf829b0b5a955fa08a51868baaf0ea686e" },
                { "hy-AM", "d210467576e9e11349f71fb150d1a014117a5f0b3c8359d956c50a20f55be91b36aa08b3bc58e8455c8cd66eef1c35dab2db3ea3ef9f16be63798918b77b12c1" },
                { "id", "2623cb874d221ef6bf4124310a1056b242296c3bc9afbfa82290283aef79008cdc094602dd7e18ef12191b9721433848999adf46d6783ad787647913bc759067" },
                { "is", "56d611a64de723408e17cc80ba47605d06ffe4d05b160467ce165fbcf206d151192ef84de658003b2bb2f9b758de9ae0445ba2eed3018e7de2a660c0d9d4068f" },
                { "it", "c538c89de4c0b787255dde71ec7a3dc5743d15db01204a11b9da3564babd2a8cca9b8ae86f760d0f5e5423cfd065ba99ae222b94aa043f5ea7e53af7a6d75905" },
                { "ja", "7a04da561029a23053a73315ea17b916060308c9780496e78a43e7b1ddac104741d58f3b965552364e753d27ac326193b3c02a9e7adde1b269c276d9738c82b9" },
                { "ka", "c3b769351554a7623f389295aa48fad6131c54e4c6f0b5a71f55cfbc8e054d9f145996121a7f49f818715c4d5b7804873f56a2abcc00e910a68f45efdb529dbf" },
                { "kab", "ee84ed31fa4ba15284530f1b719a37cd4155bf5891a569cadc23a8edb9f1fe8d36fe36ebe320c6f8fa5e71e8529acccd6c77d99789c2ffb526f273c6e1cbc370" },
                { "kk", "ccda2b1b85cf3b8f9950b4b58fa4488e344e3abc9f934bd2fdb43eaac3028ca55aca68ad64d54ba37122559f097099f2fcb780ba8ae518f2fc65d62a501895db" },
                { "ko", "1d28b007c73388ba067c6a2aa9baa1d3969e4e945bef247d7b5abe2b7dee654a1b04c08f886296b94be62b0cc746fa6d482316969e7f9e7f0e4303abb24df292" },
                { "lt", "af9aa753b5310324f573ff6f9ec7ff777aff84054018c0a4bc7a2d3c481a7322e9f3f6192292645db0d5fab5442e89259a483b8e2a85d22204531dd3d9e58faf" },
                { "lv", "213ea2ea5c351bcc7c32d3d58633ad038b86097c95df33e1994b59578635159923170d4a78405e64dab41a89c0cbc15eb1ac5691967d7133a7b4b786eaa184aa" },
                { "ms", "3c48274005fd426b655c3fb565b42bef66931290b8fa11b1d6e7cdac75de45a72c5d9409e9089e6db052541132dc8dec2cdbb7ec843efc64f40bf7eef9de4084" },
                { "nb-NO", "08b405eb4cfe8371025050d0eb525dde6ccf78d624b451b5844acf065b79b3a696ff2ab6f8a51090119b70e9e284fbcb9a26901c55515440ba690e380166f90d" },
                { "nl", "c9575e7a1af182b02a4dd79f392058fa0b9206b3cb33857a88a997bd1e09bead04e288662d1d7b857d63d94d3013a5e98ac459c2a4e73c84449bd29a929aa23a" },
                { "nn-NO", "4e4cb78afea8011b2d3249fa481fc15f68bb145609d6f3868bba629ab8ce37e4045353c1c9d67be454deb5303d194ddb2eb12f619318dfec2d0e98807b0e27a0" },
                { "pa-IN", "94e98b3ff0a379a1bef5bad44fe34d3e2263c95c649189d2e815b9dac299cb2fc4d49b96f628bf5a0e88a086a4813ebd2e286ad1a57a97be2482c058186d8761" },
                { "pl", "d5b6acfc985bf3fccc66c8ef4c2787305d974f45fec870206488185cb22a32ef86f3818ad520500111a6d1c1652215c0639a27b4d5747118272aa29d7d6d6404" },
                { "pt-BR", "5d4c86cfa3f8fbcc425efc2415479f4f363c04aec756785101e66711b36954cf084f05d7e48b9df22b6d64e45d9deaeb2163da61a6537d6619ae285235e8e357" },
                { "pt-PT", "f29176022de849c41d23db7a42370170c6be6c0d3b22a11210ceea4a2442259393cd7a6318ee50407fb9cd2acb07eaa8eb75e9482cf157feaa4fc2c7ca39f278" },
                { "rm", "c6b52739dd71addd20c27b4465de1c299a3808f7e1694d1f0404befff83f28fbf91e9664a23c4e7a0ebf1bd0478c9897ce3f46bb65d99eeea3e4f22c96bd91dc" },
                { "ro", "d08ca209203db7895029ea4fb7da94fbcdf77f806b0c478340d3a0d270ea9d35a66a0933278bbd859d85c78f5fe70d562bc0eba81e5905f7375578fe099ba046" },
                { "ru", "6c9ac4e1a27eb34ac610fa302f2ed4f33d24f1f4d1391e9761a1044772755c8bd1c74d3659bfce950240e25f3fbf406680944f4c10e72a2f1fa19cf308309330" },
                { "sk", "bd07b972f0a29b1d16019ea6ffa12a676e7d8db6a5d9d2228f94ea793834eee10cc2f3c687b95c3aa3bb56d62c6cd42f3afaeb09ccb6e52bb8fd786c04a30d84" },
                { "sl", "24b1c543f65bb01edbd11680b50efbd65b17e2f781d79f9a4ea1887cea5cfe159cecda18523746e8b286416c392e3cdbb2a5c830fbeaf1625b2a039007537bbc" },
                { "sq", "68da9fb4735401c23d340ba04ce15f7af4e8ae7503db23a5e3f22fbd9aa48d3e28ce853fde1d67aaeebe2e8345118657887527adee2011a7780328e68100b779" },
                { "sr", "33409e6eee6859a2fb4c6dc6eb228393db2f7814ca345beaa886d8d2a5a2fc6132c1de73a14187d196efa563a0082eba4659c56a94a6f7a523ddc5181d8bdabd" },
                { "sv-SE", "e2ee919482e8716df6063422729af6f22ff478f2fec55dd4d75ad23ab6bb0657eeac2dc95d1acaa8a4e72ad10d9c9dc604768c1c1045139b2646ad971de813b6" },
                { "th", "39718739663e6f3b25ffd87053dc1bd17c05eafd0bb04e3074b946207ac652de087d6a2a07dcc7c3b33054dc3d108c4ed4e0e055c100ad1556349087468af32f" },
                { "tr", "fb5ff5fd4d91910226020112c9418e96d486ca29c908d87b42e0a501e769d13841805fc0384461ebe9f87e8a96c59b2b4e10150cd982eb002992a24c466c50a6" },
                { "uk", "9d6c2f921da94f7ef5fe8e43e2e7b800035025789687db424ecc52b912c8105a0d36b0c4ae45f9675b51ee49ed9cf278ab85e3214b9f8ad48a01dba1e840bfda" },
                { "uz", "7aa7da95b7c636462bd478c5445a22e3ef292df8d3033a6805a8092b974bf8b85f4ae971b38bc7d8231620352c1bd7a3f8fec7320d063d3007b08a5997607188" },
                { "vi", "772d4353628c7003f5619a8e6baa0a3f22bffb9fd86f0c49de0497e9e85ab2721373692d79c9b93360508e1d9b2dbb50db6e2e911f8ab8df00089be624aa538e" },
                { "zh-CN", "af03f3bc077a621e85aaf009fcf9894ff206012964705deb166945e771efdcae61045345cbda5cc6bec7a8dc630e84099d808f13f9ffca97544194381d16b775" },
                { "zh-TW", "2d0637235f20570ffa4f538e39966dc719251dbaf0fe5799b06902b85fbf1747f83e67c3c77ec0a15123e3d1e787874f4942f6ab3b45c91827e66a3ea38925d2" }
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
            return new string[2] {
                matchChecksum32Bit.Value[..128],
                matchChecksum64Bit.Value[..128]
            };
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
            return new List<string>(1)
            {
                "thunderbird"
            };
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
