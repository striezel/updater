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
        private const string currentVersion = "151.0b1";


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
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "351423df06cae28715e8e2e32d74a83d52caffea4d674fc3008f9c07aeb624f04a87c6fdb7885a29f126ac2b20848ac83e7618d8db26c14fd2ec12bfffc0b689" },
                { "af", "7cbc608ae46031a83a8dba68ed0d0b7806343a3bca02d11d7a30e71ceda35fee6dd6b171fb28f8da073d7b96f22b93b6382b4f32ecde67bb40a9512820949611" },
                { "an", "d32ee84bc39ee8d6cd145c9cf46f45ac9ede8659cdacc47bed4c0b6fe84a6697c9ed1c1be069ab35ca0f5246f35095075bf22f17fbc77a4a6b0917bcd4126d93" },
                { "ar", "f51f941c52135b125c91945dc50f3885174b0b30af02d50a0884437b978917608363c1f5c16683798033be0c150261ccc139ea8f12f8a8bf1183d298bc1c73c7" },
                { "ast", "ba3cdf74d993bc94798e821166c830f92bec2298d7c800cd2b9a40a7477b7bd1164aa97469d9b8eecfed922e6202b949b93612b60dbac2822a737ec8728064f4" },
                { "az", "fcfdf2e0c91b46912d751f4e23888d859a82f366755589ff1cf581087f1d250aa7abc0fca345e3f9065c9450bc4cb0b0198c829c81f1f22152f9588d62b56ec5" },
                { "be", "846a6b7d4c93555e4107263c17d4679c12321d015303b0cc5673003f44a157515565f12f97d9f2f8f2d81dfbfab5397c2d4994a5ea99373101e1f7dfcb1f4411" },
                { "bg", "1776f8c8606d4dc81117ce7dbedb9db430c9677c39bbe05bc3898db7b507f372e54218ea1744112a554469cf840539d6130a9f0a13b4157b549151d68df999a2" },
                { "bn", "de397afbcdb70d9da346a4d03587c6332ae24ad4536a380dcbc30fd6ec6587a636f9b9df721ff9f6f44ba9f55216825ed77af7df17ef95ebea68422deb294cda" },
                { "br", "6182458ddfafdf432b93b050f24bef972b92318b19936fc653e99fc045b3230ee76117c30c4f3fc523e7fb44016cbd065f52f66c8446f3ee5f992fd7aa229061" },
                { "bs", "920480b39dbd8fa1589394d12380bb07530788d5474a429a7a84321e9111018c7ec23918b76c553d379d5044c170121e45729a2f99a5ab7db1b4c4e7d26512a6" },
                { "ca", "022263183bba1bf6033fdec778a7c7fc21f5a5697f52dbfdf7f889457ffc2cf64dd57f1c1fee7ff51587b6eefe95785a6ff8aa49bf06dd92a261138076acfe39" },
                { "cak", "b3d4a02162f6a4d2a01a5fdd963c81e6d81024b9879f2171f4bc18cb862fbada1031a7494d655008474747f36ed8b5e4fa41b9a593c0fcd1dbcf29bd5b1bb978" },
                { "cs", "63df062876e9353c859db35aa194d54b1282c772a51605b4bc669bcee46c7a2e0a0afdf3b19e3d5ecde59e2377d2288fedc7d6381016cdec048b15515d19bdab" },
                { "cy", "5e45750381077b1566d165fb7a8ae667d71a3e5ae81fc09079b1a00694ce07b2dfd28e8c3120933d5d9729a454744cf558f31d4143965909dce3ca5ec36f8eec" },
                { "da", "bdd64e9ae7b067991e4e34d16346b17dc5bcef77331f3f99eac452100d26d04f215c9aacf3ddf6cdd2f4f56101067c2038d5e31a237bd8fe01ccf66b85d2f379" },
                { "de", "e4a23f90e1470b9488958468d5558e9d5e84461867541aa6fde4584c6ae842dcb3964c1ab5c8a83f4da2cba8a0096bd7098875d9424556ad7972a63eacd3ab7f" },
                { "dsb", "9c6b0cfa94538250bc66bdaaedfbc758e9a78a38457d554f8cac6eab0692f6217adda912eed8ecfd17e482fba5d1fba0dc55ea1c751dbf8323e0acaa143f4cd2" },
                { "el", "71c9c0e79ed46d63385399ef7a0bb6734400417f8ede8e6d5ee6d91a9005f7dc65fc2824bb1de8903ed0fbca7fad48f18a05c65c84f67497a835a46ca3d7ae33" },
                { "en-CA", "4216d45941676067ce382f4ab2900be1de1095ce008c03c0c12b0a8e7af88e79750b85b57ca7703800150f966c060636d53908c4fa2ae7f8382a3351e5af7bff" },
                { "en-GB", "901f1615f1e7e786ae3d9a2da04280a5e1b101a96dcdf2a110ea46a5b04d8749f812062ecfff79ef7a3272fe1dad8e66fa017d5ef4dade72e45699563648cd28" },
                { "en-US", "e1f08db66eb53fce548ae7bdea15013ccfea6a47f792b4d189828e28138a391578e78b69124154ffea9306b6a43ac059d2e5cc34d636a89e62a159fe3ae45b71" },
                { "eo", "8d21ecb4e44945906e2ded9e34a4f71ed21e6c8aa223cb36ee4ceb734c14240e835795d56d2b6b8721f9d4659ccdcb2732f2e470c75990c80ca1f89a4d941111" },
                { "es-AR", "b32efa5b0e1005276ef1f96db8a269bfdc3e5df0e212d09da90c8668e59fa96b3a6b947b0ac35a451acb5fbb301fa9a986ddc12ce0642e95b6af7db8664c0d37" },
                { "es-CL", "478900031eb7f5f6762bfbc5f9a5863a5ecc9f59cccd7273cdccf54e77ada93714b53a4362701762dd6f4dc2f504e0e58ee08098f54e49ef9399b42a0c488856" },
                { "es-ES", "31b495c90e05b0e5f4a39bb84cdfe9d84779f0628760a38fc2e0ee322afa022ce23ffe3472e4e0c92a391ce7ff9f6711024a23213a88576599910fe693d5e07c" },
                { "es-MX", "4175084bf57066801bb0f4abbab737f95172d16a1a4e63d612586b13af2c9530b648fa10bfc2b25869d2d293ec0438920beaa2aa34060a4e19a47a876cffc072" },
                { "et", "83f76865665ea09f50bdd9967aecf146462d1911fd9162527bdbe82479ddc60d44f74e1fdc76bfd955f547c6de9afe55fbbb84058e6dea672e69d68d81e76035" },
                { "eu", "09b4f62945737354e2c9913dec7645d1346ecfc309c10588df65d11198feb77a3c41357bfc8bdb546faedb1fd505917d7213333e5d5f971084a67fa15c99a8ed" },
                { "fa", "9af47922cbca25aeebdafcee00b53ed67a7fca8373fe9810d6dc87ec32003fd3b2c128225cce00b6add08e253382a35e20ac41077d1fc72ddb747797a7ff0693" },
                { "ff", "048ef2e4c0b200d1ec2d91bbe0f6fe579e0df73ddb54242b0985fec297199577ccf546297a50aff020d80cf52dc63de8fefd1e1e6d4e90790d420f31998c2c7f" },
                { "fi", "317c2b1e3d2be1ae1eece8f4de4e3450d832d6951857e9d043fa1b8c6aeaf36f8620f2a76246beb3e70d402eb2b6d99f6c3d7be0ab4f2bd3e4632affb496fa6f" },
                { "fr", "b92f448071961f9392269642503776f9d8ebf9bc16c8d06730a103cd4a0297ee2f155d79b7a34deabdeee4f8312c0d5e86887cdb0abac494e7fa25ce46095278" },
                { "fur", "35e1b8554a0b1b88b73c1eee98b13f691a6d96dc50c06a6ed529c45031637c0d35e51d43eb0cab67f242478e4aed25719d383678023ba4fe9b266b0690c60463" },
                { "fy-NL", "1828b2d19eaae4a5326a6a8e3e8c2ab882b4577ede785fe9524a2b6fad21ae6db2a89d3abbf6a19b55f978cc591a7bf4fd3a30ec6acb88c5d7889caab971d4a5" },
                { "ga-IE", "faa291b42c5901933b4527651de81e7836c986958a28e67c2da26298a9d77cd4f8ebd5a0ca39bece410188ba83e00845f44cd10797462aa35d5f4030f9f4e2d5" },
                { "gd", "1cf44ebe0d0296575703866b301fc873b6f0106e7dafbe7632ff0f8cef60e7e8737555824c17faf6d9ad7662f6b46f86c8e535af2e59b61b640fd31a1c186651" },
                { "gl", "74466bd423c04de29bc89d68d386407d61f5f4e6d05fd1188aa27f77d4deae4619e73171ccea25a1f69896626814c74f07eea96eea4dbed8b089b70fcbfeda05" },
                { "gn", "d38e165fce470659e892ae9099af4f1b92dd4e854b5669ae34fd536fcd0d95b08c56f81b39ca55987a096c3f143f1c14fbe35fc8ef3da19092f0ccf838708d10" },
                { "gu-IN", "80249d8458b915b0aeca2bff15bb6aab0759d48055c3982f4b1e96d9e7cfaea50d5fea5a425dc914e5aa665fdb6aca8ecb193fd5d37d3b8f9878fbfaec76c57d" },
                { "he", "a56b3af03858def69b507ccf10c4c544b1d077e97b1437bf91debf9c9bbfe47a02f9ced082e0b98ddcb1120ca77125acd692e79cba4d3c670f435b83d6013727" },
                { "hi-IN", "50b784f84ef405fdf5fb8515e162f8962394f2dbcf8ca65b677cbe729863bd5c6d87c550f2a14782a5cf754aba7bb1c59697031621eb278fe58fe35d2fa2473c" },
                { "hr", "ea3e3b71b1b69ead553d6f1a96895c9cca4d6fcff9ae8f93b78023f638ab42b44fcd417a21330366d385283cfe684cf6da3ada74980ac568ad6c06d3dea6d2ee" },
                { "hsb", "4e784884a6aac8810217a8925ac22cb16c1dae419c7a7e9d5ff8dc02b79e39673f2c9014edc29d08c9b9bc869c8416608c777354b28e61f2c219286ce1bed17b" },
                { "hu", "960a5cc567c69734cdba84755142bb0f7bc0b947f83f957fb6581b392fd1225f6591d72dd29b47b7a965c20e265dc5d2bf85f6a2ac50509c11c3d238f61c9101" },
                { "hy-AM", "1150b0e5fcd325d3a2c810ab95f750122809618bda0be0339c03e27ad8de668054b51c011acab914c8fdd87b69a0bdb4fac0706a644e630c71ee40ac397b1ec8" },
                { "ia", "48ed251f462b5204031afee7fbd74001411b84db76d4f97b04cba90eb9d514efdc0360635715da19ee8da346ba515aa158454cda4188a5d10d5128ef7a2633af" },
                { "id", "1b2b4589db2f36c421ea88fcb7dd0776eab218a380e6e7cc561c1309bb81cea05eac787ac70ae7b7145abdb0533f4fdaee83bcdb73415f574c6bb6a0fccce9cf" },
                { "is", "46d4509efb39ba77402d7a7e79f5aa0fbc3919e3d6dea17f4ed66db7c010bf62d619aec1e3846bf0242c2e471b163560467d542a96c35ef4d463d7891174bd61" },
                { "it", "920d962127dae06bc05528cd5c2b4709638835d6ed775141c85ef049890fe1769a0b8d1900d2454ce81533cf20d194313b598e9842ab24231cf7709ba3f02242" },
                { "ja", "a00b3632206aadb08877f494d002069565af135df4e95ff0400b3c50f03821778af18e5ddfd40fa224a1540f0890461aada6831f5361de8c3f282bcfcc602c53" },
                { "ka", "a63510e8c9be0ddf20277c339eeebe443215a2b3ec177f51b5b25439950bac5dd359424083fc705fd0f5db14a6ce8fa6855f8cb1feeec7065154931d81d0583b" },
                { "kab", "26153b5519be093b2699eba102f27e31e1f17b7980fa5539848713b4bbec68943de5f0099290b811aefc17a61d9300f3469238276ecf63aea7705761718f48ce" },
                { "kk", "b702abc33f274f23472d851b6a5b8a7fdbb86423de4e27ba6447f0c268314a8b51ccf8405b0325704f86d315425bad19b3a960b516557e33d6d9892c7790b00b" },
                { "km", "af0c866b4029d7ecc5c993086105e29be28127c9877dc4c51f929e5c464c52b41be23706a2e520ad7cbaaa081b9773ed1d46f271b520e7d505045a0860b4375e" },
                { "kn", "1ce31a3289d5d086071df4bf13944a07bc2231f8984bd248de38b0450204e240fe0e186bcbb600f5b7a8a7817e0244b07afdce06c57fe107689beaac26e9c1e3" },
                { "ko", "0f99c694f0ccd41d8adc251fef44d427ca7b9c7a2e6d9297bf49c6bb6f8e157586a338d72ac18afa76a7b0973030386a5ccceccda06800834c1288902e4898c0" },
                { "lij", "e2b933721f96093234e82bfa0ec5292a3c303e18716fad2bddecf268192e3de3c9963248a58c4efd3c4f040aab10e0e0851cca46822e64f9210d412e2bd39230" },
                { "lt", "68de88652a10b4850f300a4b1ac2b999bd6cc50205ab38598443323189d881531f26c60917c415a95b39ff219e4521b30942689c0a6659f2de7cb35b9a9aaf57" },
                { "lv", "12027b0a8139c1b8439196ab78d92ebc80faa3651c69e0afb8a97a60aa8636de41dcf48e0aa7b345bbdb52abe901935724bd6e92484c84656036b26228c6a235" },
                { "mk", "b0632f8f38a40fa6f810823e52c8e24bb0137ce433868fbeca20f9214a94d97abc1edf7426d597d431c612b5a2c10c1d30831e99dae098c1c92db7ec7ea6d528" },
                { "mr", "5f6ae74ae99ee2aa83b842e3cab2c0628feb70da97bd610a3acc617f43d5255f45b7fe2445227d1a9d0fdfa67951b66af8d17c6ec6201e4b67a181a7ca7decb2" },
                { "ms", "f1a762c35c1c08a3fe01868202163ebdde66e69262c67724c1b2352c94391df7572f170df7d35981f141454d877d380bdff1f9132e9c848b9ee59d5d6713344a" },
                { "my", "2cae448152ddc97ead8aee04dae73defbb0580d4013e6e0d666d0622ea5d7ede93c954879c62c70d59e5d2f3aa9e0f1a9c5bb387d9e6087ebc7e856dee7e37e2" },
                { "nb-NO", "6a62a55b5fe68667ebf652b8a760a24cfc5abfe23bb86fb784907f133c19b4c21f10b55aad062e11daa4107725b40ddbce828c49a7384721d6acc7856d40a192" },
                { "ne-NP", "39c1161749407b7c98ad9ed1a38bf2724a2dbade27a14760b964288bce39074a16268f8ddaa05151a58329cb80ea0edcda20c51b8e2268d4cb8ad06d6a794370" },
                { "nl", "630bd7f1f5ee71b767ce50cc9a5f8336a3f86c7bc285b6d177c72195f8ee2e03ff0f98ab772a74ee259286b59ceff3cfb7c20a01e3071bf807de367a4be38203" },
                { "nn-NO", "c1e195ba97a84ef95a68bfecf7a1f776bf48c2a30859befe53cc0f969144f6a90c0b724e9748a3cd0720fb2fac4ea69ada1e33f7acf214c99594369b70338e5e" },
                { "oc", "930d3f385e4993a0d7022a81935ce96c1a4487db458d3d3ae8420cdb92b5df8a54d6b2f984a8080432a36739f677053ec11781ec83d2b6d1e90637560406a458" },
                { "pa-IN", "d0de7505152e0411ea6e352ab028d1d4497a66ebc3b618181a9671b2b730756b568c9b8d6492f10801d61549ee0459e5a4d80003b45a33ae2e048e6e61790c7a" },
                { "pl", "1ae20f1cb00835972bacd6fad76160e2e8ffe07fc036d924e0af6d9252a1ddf7ed82abfa61755cb21adced9aa421a2c1af12c1fadd5675c0ac52bc21b6e3204e" },
                { "pt-BR", "7d6c4a2820c3e700a10e6c375895cbe319d6050dbc7c56fb22e4d1ebfcce265e9ee0906369c0e3fb20890b2545c006092e5a1332a67711a1300c655eb087e66e" },
                { "pt-PT", "1664a00bbf09a882f3e9bac50952546b91c57d47708b7a480027df2c1d573d8c89feb3d0df72b102f36a1b52b3828d3f55dd99f8363b85b1a8de42f14efcd369" },
                { "rm", "0046824a1f2ab8ac7649ca4fca150f76a05ad342034bedbb1b6dff17f924a2b80c20256fce5435373d3ec344a70d3c0328ca0f20c9fb08b1aa703a0a5618baeb" },
                { "ro", "c85116f0413bfc091b25a095e69d5b72db0aac0f22e31af32e2610a81bacc11f7bfe0d562d571a1d2ae0657d34770d7c6fe0d6e677213403fdbf81267b91f2a7" },
                { "ru", "65aaa1ab3b48ec9867032851df4752583993aafd0f151e611cd2af10b5b20c33d3171c0d69d6eb245762921e7a80047ae25a3ed1861a405abd4fb524e42a0e25" },
                { "sat", "76f78a830a3cf8326ee9de439760881ae8ba70a235d21ff1eb66a7daff42ef4ea3fc3da716105988ad906a2a1a3af0bf79f1583794cd6919e25abb977c904d14" },
                { "sc", "9a2278d79edbb5faca38a1051fe33d53c0348ea0190da07aefa9f8403f9d0148b51f9e6674bedf02d7db646765d31927f816e6743541676c7d34e2ee774f5130" },
                { "sco", "218b72773559fef3a648cd12fa3bf32700158cf50d0b8a3d7c8c6cd1f4a89dfcd455ebc0d4ad60fa8ba680ad6a8b6b0c5bdc448a3e1cbfa8b24ac627d22f9a24" },
                { "si", "8c08b49b613fb411f11015d860915902a045cf2f84bd0d11ee9f1a779963f30e8a6f8ec6413a85e5eb0bec46ee4a29fc0702c7c5f2266e56749241c9302bd472" },
                { "sk", "c97596279a013b9996acc1eb416081cc95704553efd70e1c1b72ae8009b37b935d640d1d8e6fdfc40c37d02aa7d9a5ffa1d787498efa8ef755d141d60abfcd4f" },
                { "skr", "f88ee21c4168aabdb8e8b1993c78239183d0de4ca1b7bb305c4f50954df9a8331a52e3ce2559ed4569bb2675a783e6c616c9cd783807fce73610323857571a35" },
                { "sl", "917e87748c40633fc539e48df544eabe151d83f9ab835241a16d5e861a2cd490a36078c84088f385f73d2c970994ca077922108b0f5b07be876a09c0be779673" },
                { "son", "ac074b9109fe1e112f2fc5247d3f3ba256b69fc53fc0dad7a02fc426827b3641ec79b7e53a9c10c996779ccf1543e826ca1f55cd7fa192b03acca6fc03116c72" },
                { "sq", "67a37068f821008c15354cc0921909dd00006a6108e7c17dff8fb23e30e0ef4edf4a91b7f7ca1a9b887eebb38dd1b8a0e44745912a4ddffd4f83d028cff8bc03" },
                { "sr", "401030ce0ba1f7510903c21a0442ead52cc15b5d404e4a82455a6566993d0e1833ab688bde373fd5a96e08c97773f39e5947a5a1e77a69646938f05076a0e57b" },
                { "sv-SE", "f2a811b47a37e1ca729818f2d1ccd712ec7d98e00b4c2e72bb36683c460bc7a5d80ccc739ce6019157772ee8bcfd4bdb35b4c95afd9fab043f775c8f2663c72e" },
                { "szl", "2b58c3b4ba435e420b1e88cff067d81f3772d0efd23fa94bce2d9c94a1ea501816bd0d46ee754abc6f51ac093609211d0ef44294aed65b5d9e04c43a3bd83aa8" },
                { "ta", "39da2ed7f9c0a354bea93bacf34f50b12923670a9c77570b71471bae00276ef7cd2ee946982dbd2b31bf5951c42cb77111bf424287454f77334dd27ffc37421a" },
                { "te", "c44907228768ab211d8547128661b8210254fc24900b2b3bac78553b42eec02e8d45647912498509dab6969ea5272a95a51c0676983adf435b261f69e571f38a" },
                { "tg", "579a7e9aca4a42bd75545eb9ee4ad5744fcc241973207291a5ccb284b5c107bbbda73a20964b60217d850767e83203b66210b3a3ec3309cb319204a1b796f57b" },
                { "th", "f8d30dc77ce0eea2ebae9c46c21ac9f2768a1e89622c02f651292b9b76caa2738a2305c5a4e41678a3363440bb43b5e5a98842ab1edec72866681b125f964bb9" },
                { "tl", "3833a26ce82b677faf7a6103886c337fb56b4249359aa58e709c1c18c7a05f75bb712f4764e2ae6ebbf65a7647e774b65b6d340e7cfcfcebd06e4d9711693337" },
                { "tr", "49b3d9c0ffc8f9ee0cd7954ccecce7806e6ceebd964652bbf2e4b9f9e51c9e410fecdb40be1d28e45991b567ed1c8621a342830a9fe0aaa9e9b00eabd94fe076" },
                { "trs", "ce0c3e6720a44f6334ebdbedef465fb7f504b13eae2cc563471d2bb6e2e31a4d8ba968aeffccb36711364ba1e8b9a42e8aca51f6705bb19ffb5b15a270eb8206" },
                { "uk", "12f9d92162b7d099a0e935fa36232adab419ec477cb404664859c6bdc63a3ead24775cd97ff7258d8bbc0e7e0ebcd5db9facb7dfcdbc84b7021b5c76337ad4b8" },
                { "ur", "d34d30b6cb97b843dfeae7d9d6df083d097ade68fb0256b1f26b02e79b3357637504daa6e0a57d2307d4e4f62bbb7cc6a1ac80c834f7b3baee6dee892e8dd00e" },
                { "uz", "4b2e67406021258f3325f704b65867d447a70e1ed705b7ceb949f0229a5e1e60b049e0d59a5a524ac6c3851f9d7ff8a9baeb6eac76acf7755313281b895f75f7" },
                { "vi", "71a450e6f3e4bbf622fbf489815419774e6df9280973bfb28d8b760569d007b785d550a7b77e1658563dfaa19db1537a6d55a4c63827b6328d76893805d19bda" },
                { "xh", "2df90b80cbe2c550a5fb6213c9f6458cb4e090cfd16f9bc9680cb784bab7e66c4535edf9832813bcf9555b520fe66f9d492f1deb99d094749575ab3dbec10425" },
                { "zh-CN", "7f58bf6edf6a98287399a78a569cf06c6d6b4d3f898810561d3fe3bad7e960883ccb4858fa41111369acdb438ed8bd7fa5fb777e730ec594a1572194145401a9" },
                { "zh-TW", "967c78e16aad067c6073bf9289e1d647c45fa04ae25ae4b51c2477a60cc042046437287dff7e4e74fba96beed7ff0f1270656b3789b61a3ffb9f83d614802d5e" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/151.0b1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "9e57eb9591d7dcc8bf79214cbc20ed83fcb709f12edd3d65ff862f159cc576e4311afae349999db1f23855d0dbdca4af2c3228a3fbad3b69d00fcb54bec96ecb" },
                { "af", "ea05b321b0353f190636eb434d8d648479812c97295aaa538bee510034f79ef00ec73495ea92b66bc612ba42562e9937a4d60d327b398072591548e594be8f5d" },
                { "an", "53095d43fb7de689a2d98762410c7c026c73fa16ce6f517914625c37b20ebf8c63a54be0f8fdccf94009d78653a07b8e547cab55604b7a054e93f185aee8d221" },
                { "ar", "91f4e3c34dd227320e30a337256fc0154a5dbdd30622f63db6d12db6a1ca0f3f798049bf01726d148fe58e285607aa3571afe62d4bbe8e199d9c393717084d12" },
                { "ast", "b4303b1ab063216e24d4e295ff55172b17fdec71d17d4983e0aae1f102cdc3188088c9f82a9e6fd068de89e8dc0eb7579983c10f17e12ed115607d627bcb7c21" },
                { "az", "290af5cd463e199b7fee373359a2ceef3f5084508387f88e3dc8cb54f097985de3580131ae145757a04f9c38eb6254482fa3632f4aaa215b6d719abe2d2161e8" },
                { "be", "47d8198b581e3d3aa0f88585e6b6c8b67d8713e7545cf02a05cd9ffa04362b2bddddf44368c6b2261ed5dd02de8601a6154664f8ca61254f2db6a11d1e9d7fe1" },
                { "bg", "94eb2a133c2e2d36846c92ae341dfabe1290185f8d5d01603d1801c1f2c23fdf547a47d3a9e4c59f61c449251414459a0ec80cb7822f3e835932c40e8a805a56" },
                { "bn", "7fe3f78c282e7fb097d431f4b082a9aaded0fb1d4073ac15d62656afa9946780442f85667d90ecd1219f37bff486b1ad233479a91f297558d384b5e7fa5522b1" },
                { "br", "9773ffcf8961242371ea7f7ca6abe39d79248a571ae91164abb299b12000ebbc6fc08aba80c6849ddedb1eefdacb6227570426904f8a94270f82e4cc71e14860" },
                { "bs", "d59e41f5c4ea29692a168b9b4fc60a16f6258ea88b40e23d35cd5ba4fbfb3a902be5aeef85fd3f2d229109b6009c3c5ea10f9628afdb12df92086fdd1c988fb0" },
                { "ca", "aa66f04cbe4e1249bb3659586740da9711ed532e51f02f61c5b72ab9b569382721a07b4b3f7de3df0417849daf8212b4bd682be26c7154f583e991ef67a93657" },
                { "cak", "17b24089fb5f11578d5681c69b58d0f40ada768f95527ac87233075e4eb2000cef55f18791cb591b87741d8f27b2a0421c268419bb532c376cdd837c5585b6c4" },
                { "cs", "9f17f8aa1e34424d562ea59a7b1d9dc4c1c6f8654a5e0f54482aeed25bea02d6e8376a56edcb5312417fcf650fab0d1e336aedec333ba74e1954a2196dc6e650" },
                { "cy", "a307e44141891af6d3a3205c8f5c125a97388951bc807b4bfb9dde2a73e3cd7cbb5b31efc28c5a795c91fd9ffca42220d49fc4b9d8b74685fa97f10384d40013" },
                { "da", "03ff64ef25644591993fb637a55433f7b7bb653476d85f55c824baebe79c75497def2c099ec21dcb33ac54b0002ad81c8277a45f99960e6f150db39f611e613c" },
                { "de", "619bd86b8b043576d40bd67f98fc1cd19defc3564b8fd965dbe6982a22f478df5933da85532f962b787780d0ba60872ab7ecbdbdb8875f9db3514185996d724b" },
                { "dsb", "41246f94cb837d254d7665d9565d14b01967b09425be0990045313092418ef60ac1267ccfb9291850c74bc664a42baef431ee1c8b4529e0a60c6e7934d81ceab" },
                { "el", "7d15fb5e0a2ad91cab4462e54b5b2c1a7d990125d491c5b6f9bb37912e29811b60fc40e4bc986dee34cfdcedc14fa32d257a824bdfb2a56e60c7077023a59961" },
                { "en-CA", "ff5feea43c0c3a7afd1daefb43e30ead840129b6355901726fcd1e22dadae0fe4f88e13e9a17d8037572ef2dbc0bbe1754db2c2cc2e078275eb5670f25805d45" },
                { "en-GB", "12c0f997c3cea4f815b87e0c1ba8a1c8712d57119c2eed9bc1a9bc108d33cf807649d86fd13af53ff9d8e0c09885ec7d6f9a49b5a048922bfc8600b38fd50b4c" },
                { "en-US", "68ac0e8607976bd4d3c7f9dc87033c8593f40162b05cb9b5b6b4a51c630edf4498f49df8753002dfd8639522d6443d491f59d4eff6e1d1e400166ffb8330cb36" },
                { "eo", "6e2ffacf0782ff6f7a701e5b2c6a9713d995a86aa38da4d9cfb110ed6c8664e3e1265493e6d33a5a8603a979a33d95011929519c6540d828986181bef6dafb9c" },
                { "es-AR", "e4dcdf85cc5820d878f43af3515a7c613bf1090a12a11e4bf46dc20a4d2747c2938f0b13ec327d18cece412add83df992e3f816d8d553f9c17de89f0b8549375" },
                { "es-CL", "abab26600d3e79e515bef74e578fdb9201b520494fe613c9d1581fd698a2279e90824b15d569e54777c37371fab882acc040510c8205e26904bcff88180bb952" },
                { "es-ES", "adfe2b70e3a5d0003746e24f60e7bb972e873cbbdbaf1f61e45beeef32ca1847469c9310719d980026dea3c85dc669153924c9192b6477c7958e97973b385ae7" },
                { "es-MX", "333ab7339eb43de66ca1e81f4bba13e570161be90da003ddb19eff86cc9a258320a79c904ee66f922c445903d1c6c3b7888374d838fc908fc78aee64d258604a" },
                { "et", "893b5685025c1be48dde955fcb475902f66b51b8b86d197dcf7194ff0ed2f7701c57dec54e5c30b163ac1e45baa8907dbf4d01f9e7e1f4d90ff74b8dbd70fd3f" },
                { "eu", "be1808d4dcc2db77e753c7e83531cf1b994b2f00f83d4ab788ce95930f9af678bcf7dd027fea09c079783327569353ee455ae2ca5d30573debac3ddd20344db7" },
                { "fa", "507209b2793fabfa61e40c8f806d0246d1fdaebd4414f5632b39fdcd03fe4ada787ad5dbe0b29aee59b15827cb46151c2d1f6730ed17a7019b87214a300c7ca2" },
                { "ff", "185b2ec459db0c3b8bfc9625397d37c80d5f7e01e59d853fbe6d5caae4ba397ff6c0e9511c0de6a05244c4c18b985debd19d84d641c55dfd5556557b604f0084" },
                { "fi", "8195acad099fa2b154c2af404f66f70be3d16683d5186592920bec4255daa11606c544e48a9c0695b78594c10fe9b8ac12d0d1907bea84841dfbe6d0c8467f72" },
                { "fr", "57dac1657315d65853ae38855e217215ec7aac71c53d2d1e4c3dd7ef073b569a860eeccf9ed635bab3cb1853a179565c1f169d00b0dd5afb99be869c754716ee" },
                { "fur", "4468e29d84f5da8fcd322e1f70c2e06e7e54fb029b539a9c78d6e736f07137846bcf6dc4c3379c96e251e9944da6cd1273331958f06f4e567d238a29f0681c9a" },
                { "fy-NL", "c318120822d986052fb379b0fe8cebc968818f80b5070e4d6afa70fe28b22b4ae90a551546da944f0b6638eab859d48c07103ab6dd7ebac9d70c50f923c2fccf" },
                { "ga-IE", "fc95aa78a3c7c989dfee6623d3eb763a298726bd117e5a1c1594fc93c2b747626a097fe3ee6dffbaffd72e368f7bcd478187fd99c6007b78e5ae7136aa991e07" },
                { "gd", "e8b3dd13c33e846ce3349e4467e106ae4e094c7ac805909bb3870f9b48b236ab48d621857329e217782d91c6ec57c480ef78ed9fbc8a4463bcce5c2abc3b5494" },
                { "gl", "55d5443190df3bc1befe49290ace6e3133a0f88a5af41130ab1ba1b6a9318b4b817fe0b349ba64701e5c7f24a0087f5cf5347cc276c4dcbc4aad614a3e5636d0" },
                { "gn", "93e19d78e371ff2984d6168aefd99b10e628232f2748e7bf9ee550b6efafe37f7b0d42b101274ac6ceaa6c8b5c10a18468cffd007b44fc45314e3168fbfdb86e" },
                { "gu-IN", "5a6bd2aacae3e6b817c26397f29c800ab60392bc77a12eebb5f957a3902eecd716dbe492a9d391ecd405852105314d1eaa344e537472d91704a36e92a4a03ee4" },
                { "he", "58d5442044af9e6a9cc631392408c7b415f9463c07fd0b27f6eb632628552d0ef5d114b0d2aef30b9c169ee534f14191ae8b8d978874770ecb3d22b1f204a437" },
                { "hi-IN", "0a71f853a3ea6d9db02b3c0292707f662d60ef9fa4a04f27f8bd28e2a7356ddddb8769c6c4b0f70ea7710245d6f86f1a59cccbfe1a84e91e8f0cc573dea4716c" },
                { "hr", "c8a8d7b949cc4c04afeb1e01c223e3ec9c2cf3d5dab638801779b6e1685af460578c03f5a893e58050ae899dbfa96648de741bb8e6d7566898eed14536221d73" },
                { "hsb", "1322dc1aa9b0d52a0fd3f47c5da98ad50b5cf7183e104ac3482ea9b7a86c8bc005565cf4c49b4646b7956dc2c6416139a9cca96308909ac0fa050615af0c8bb4" },
                { "hu", "96ab87b982f6dab14b38d9b4da57c2a80b8b55350cc0c8495c5d791b5ad757c7386ef589db8d94f45160f3a7f9d024ded1317e7e40607e2d567284ba0911837e" },
                { "hy-AM", "21b8ab0a647b3b9389f12c7a62d840f828aa673b27b8e3867aadbab4a4c70361b387e598ba7c20bdfb9ca6710a83a72ba7d539e0b87a659ad4a3fea0adf25cdd" },
                { "ia", "6af829cdd4b35eec3d4b471b6e11f25678144f56af510bae060ad842038bab3d2eec4af9bf4e0862ac659cdaf8456ea17a5df748885eecfb54a5482319f4817b" },
                { "id", "7f8961da06f3c348653802a3fb6290b327b3a569f3bab088be34bcc447daf597145e37df8ed3f955411a0dc156d709685ed680aa403ba926b506d23c54f8e043" },
                { "is", "da4fde05f84df7e5af3d21533b3f6616427115b4a3dbf0f4eeb9f9d72565ecf6d9e53c62a88987fc903aa20ff06229f65c7f584b06834aef46e0f0231a07327d" },
                { "it", "8857ef9348dfeb02585b2076660c19209c7cf0765917847c8621ec236489daf4362ce6349b8387c02bbdfdc693ac9f2e59c8e6213f0b662b62baab0e48bd431c" },
                { "ja", "ad347dbc77f83517b8b494460a4655a92aac6c00da37983ea96ffbf69e1a5d44d408518695de0d733fd78894b02550e3a1a9fe09dc4abc844d730c05704ce316" },
                { "ka", "4bacc18892117d894361084f70128a1e85c8c2557918ee7a00c7bffbe56b0b52cdf25aa7a91a8674cb8f44aa534715d9f86cc9bbc3623653ba61477aa8703cc6" },
                { "kab", "5e1bb0037642e8a780f4138ff928b19b7fccfce15b23eb3393c2883513fcca51b1e7b3eb2f056df3a12a82aa80048fb0c3821f2eebac403a4d3d6d9161fce961" },
                { "kk", "25c37d41c6d4e0994dab8f30153e030317bf89b68d1bf0fde4b8b88e11fd7ad968d27df324a733f5453f639bb962ccd229c1450f953623547de1fb8781f6eef8" },
                { "km", "a530f7e56e7a22c85b26c58e6513544bec37e8184a075ba59b78dcef943378e65b612f107ad5f08690d817d6e1ee0037e1bfb73e02550dff28e8af029a96dafb" },
                { "kn", "2c5ec90308e78a0b9bd8d0f7c2ec94eb9a6b1767488d3de7bfd0ff6bb25145b38a55fdc6f8499d5274a8439e4bcb8408d0ad890836c11695b7b14b8787847c5e" },
                { "ko", "18d0bda4ae0ed5580126ff0eb3e176cac6085783e23890970dd5fbe78f6a6de18bde6a309cfef40a8e44f7e41322b15f04766806710af1d1b9715d915bc3809b" },
                { "lij", "5a441ec6f92ffa4bf51abb9eef6269253ea6864afffcb52c603eb8b13b9038dd31c59c45a6a10bcc9096075d33b5bf156f9a89ba0cd89dab8c5246686f730824" },
                { "lt", "400136bc35f9192f075e31b1fff2a6b6dc421ef49a27e248c1587b3282df8cd80d37cf5e8757d59f56dcb03e13c856aed3470656c638365c0c3917bce8204250" },
                { "lv", "9362c0a161959e85909189fc60412fe2a3e0dd670fdf504d115b8a0658df681683db282db8010e53795bcdc783e832380069b9cc2bff656bb1953c68730e22a7" },
                { "mk", "4e1cc0e213cc3ad8eb16ea2df758f45017c5a66580f45664432d4106f2068bcf255b63a1ccafcfa6e5a8954d4bd48ca2ded1e94000c3960551d10114c76a1668" },
                { "mr", "63638148610af81f10083b9cff4497dc34b5bc1ef8ecadd1bf2feae25299ce58352ec6959456d599287a1f9e7ab0de7a95a1a4ebd6f9b3cd20ebda5f6c106663" },
                { "ms", "2d1bc07698e80c61b97243b037fc04fbca7bda3ef697d103503e151ad6111a722e5b9cf28b9fa7074cc9fa8d3547871a020d5e02ba400ac15d6a5f3c1db77c91" },
                { "my", "53ecaadb6dbd3e94e01b0bc223a813940989007237f6b574a6bee1ec3801a9567853ad6809af5a9416ab4ed7b673b798565e0b0baa60cd3ef3460cf21a183386" },
                { "nb-NO", "73d67db27111b9d8ce3cebbbdc49b98ad361ee0a95932084c4ed378d30b85343dc3583efd3a8a0324f502745d870b9697efdffe5f282f87fd0ba74bdea48ae33" },
                { "ne-NP", "bd91f4148a5d47c0bcbe1d6937cda8da2cf658a8acf90103a355b2f5a40739e6d9fc7a1632ffed0bdc063b203a9edd797a98ff0b764a85996c93daa3475638ef" },
                { "nl", "8aedb6d478bf2b6f2cde2633f49488b0db808c503ea0217773a3862171274b2aaa9fd6acf8d0b2a5f8b2487916eee8b39ac2bffe53ed38444f6255258207c0d5" },
                { "nn-NO", "8db681dd02cf0948934c0c3292725332d2fd296c3b590c708a6438dc0d4c78b0ffcf46e85ea5d75ad4e37f2b1058248f71be05043d00298dfe8fe968a5bcca4c" },
                { "oc", "959fbb2ff1430d1fbc81d92fe903d5cf6a984dd20a9b8d82c1915fecb3eb6cee652af8d9fadd02107507fbeabae68bedd699c8463fbcc34a5b973fb143c71722" },
                { "pa-IN", "eb4cacf64bc4e42bd7f39717a4b7315b5763597886af0e4741e6e3ceab1a4cd41a251adff81c99bc37c477f0193aa78dccb47e6e51b252a045b9aeedf2dc5d24" },
                { "pl", "6a90d1e4a153a22d1e78790b312ef84c08d1638e3752789abce0f2d7b7b541198ce95f4af1793c9bfba7e21272f63b999e30e61d6aea3dde95a1abab2237ddc7" },
                { "pt-BR", "086e7ce041a58493c8031011ae931f38ff4a8b85ff0c44b4569979ad7ee4f25307814f75b323122e49128e83a18f00aab80d9d7fafacaf77e8b4a43f5806f44d" },
                { "pt-PT", "b7a712765b4469aa5aaca6b3644187bb56ba8e5e9556bdfc224d46d318e710d666637f91df2fb6ab44fb53ff61d9c0c249dbb66bc48cc2adf645019691c8738d" },
                { "rm", "0a49e4bdf4907d4caef5a7c43d444aa8af6f374cb54e1782c353002c799bd9f0105385dbe9b5f8e3d3bd7293afc7b3d57051e2adeddf1556a95dea946a8ad565" },
                { "ro", "23fb3d6885f2f1b25bdfd3f79e074fd082f48050eaab8ac40533c0d34065f5401aa7f430c30e7f4f521659fd4bda903f3fafe7a16ff18545223678bdd3d2bfa3" },
                { "ru", "790910d9582b24d941135959bec964b86f8e04bf81ce47074f86ff8942011412bb018728e810f436b6b8ae3abcb4a7ece3aac9bf5cb764bab541a8ed135e4f7d" },
                { "sat", "ebab6af1df1531ebadbe46eaa8e8ff9d08dfad5d7f6d789cd4bd7f064f35d20201e953fc4180423257d8dd4220c3f16f666d7d8288899c09e547cc5d6410a4fb" },
                { "sc", "1002d9b2503666344bf4e79954ba1faf633e945a3d8718a87676256b412da31d022483666c23c28df74655e1caec3b00cd0a8ef1f896d4ee52ddb706b6efcbbb" },
                { "sco", "d0cef60e80b1b69612dbd3b0df577d34642958d3ece716caab79e942f9a2140ed2193e1aba727055e32c4b3caf39421dc980f9cb33c24e964ff7637a74cd2a8e" },
                { "si", "be72551d6e7bb41a4329ee70157d4aff02351195b880ec1a5da7d7534d9229de05c29e21ab4ecaf8b2af642560ed783280f55de48fd44069da59815c7b04c18a" },
                { "sk", "6b6e4bd9110f3c25ecde215934386f946911500da3d9e130f2122885bfdebe1efb71e9f9322f7434d1cec387478dfe64a431a27172ee3c620378a6efbe515901" },
                { "skr", "49293e063a668a16f4437c61f6b48f2fba5d8d1fe0d9c929d4fc0cc73a1ba201b851ce57fe2b84f6dd76bbc2d1196bd8acf0e1015296686c7a8a9adb6c23b25e" },
                { "sl", "3aa78cbcec52809d56c16131de1e4beecd1b504c52e8f7fa8c55bf932bcb6b4efaa2e6dd3150c217cc0e531d30dc7808d3e9a7460862f46f11ae95cc25ae53fd" },
                { "son", "c5fe0f367019e2d02a0ba80bac00a443620c5f0f06ba6147b3b274bff12c30ef5f92b7f60cd63fd85b32543af7415db998ef5908d05492cfd587e091e1e22a33" },
                { "sq", "aad174f4695bbabaec55af36492b8bbd2f09834d8a8c65bf68442c1d6cc1749dd4458ae6ed409ce528fa11bc14ae5e7f02afd34a229788bfeabddc897ba9c1e9" },
                { "sr", "5e6ceed28f67b0063f959e782de2662c72aed3e6c73b561ce6e1e3ef4c425296e5445acce29b75cbdcb0ce60358ab7869cc27576f74694328bd2f7ffe83cf7a6" },
                { "sv-SE", "f8e146086ddde5b3f70332e76abbb498cb2305e53d92a7d357438531f43ce3087a37ad0d28b5d34edcb48b4fad9d5725e2df535a823bfbbacd2f322b20d565e8" },
                { "szl", "cb1383e53f8e777bda46c2045cd5c563956f77472ef37b75ef39178a929934ccd32175c0170f1bb38a69d65548c6340f6641ac18ea832123f1bfcc66a2de4c7f" },
                { "ta", "e71d6b3cdd4086e00ecc3f3fc88911b350df84c51ba5739add2fd768f2a57420d9c1f96fea9123b1f135faa217ed9c88ae2ec3268a629176388c18d992f0b171" },
                { "te", "843e409f5d062ceb05000e62e98639af3d09f2e55d13af44fa26ac0e95d565df9b108a240874376abd47457f4cfdf98cebd696a992119192510b88e85ab53d97" },
                { "tg", "ce3f332787ac92186321acccaf332d3eac7b8dfe20dbae46f8d722e4d9ee0607120c581d4006165c14c1e1082c24798a55c6c20cfbc51901867782a560a1c9b1" },
                { "th", "9458942ab1434d501a667d210cfce38ee7fd3ba627a91f784cbe903dda53eb6e0d51ee6dae8462bf08ccd8be556b1ecd8a1837101873096890e2c4789654d0d8" },
                { "tl", "37fff2fa4d84457b6c1982300e9e15bdb4a9b71f9105302b513588c339a2aa2af329d795c06fb9d868f54aafc6739f75450527914627e009044a1b6b33ac1003" },
                { "tr", "02d81090276d9c6fe5cf3e06c4c9de7a191ecbdec52d6afe99f37068073441ce1bb3272e826becf346390840199cfd380101943e7306d9a53f6e1715cb50d855" },
                { "trs", "68b3de048dc74fe55b1451dbf68806b26bb9dbfe28bcae10e73a15187417c64ae9f548dd03a033b62c3f232f1268ca074e598229fada8b916c34ef8c8737ac2b" },
                { "uk", "959e7bdc360ef46179901824f6dacc90edad9803408e520c70efe3ce601787f965f98f58931473e542b98bd552e28ea6fc171c7eb101bab536588c363885d119" },
                { "ur", "0214310d1afdeec456e32fcd63f5afeb2e2ebb6b4d31538e39aa3c85a43b77eb4b1d496d831693396e106cf91c7f6592f74f7f2849a579148c7a35bbfcd38de9" },
                { "uz", "1f58dd237c51d4a920f19b807850efbe6924bdf4abc74cb24fdc73793c8dfd7b9d5e00ee29a0281c3e86d9b812faf3a0a83883c59d988a3bfc1a199027d8293d" },
                { "vi", "409496482e3a5d468837a2ab369eefaeb6f4c2b906003fa5795a42b458dce8c30646fc00f870ad402fe0e687037ee7af539daf3d5460eb8c867c34cb11a5f3a0" },
                { "xh", "bbee5d20f8793e0900b7f0592090a763d23e5574972796ed1b6d002df2fad7b07158a3f28b4169cf595af37f51b42585da1e3c82f3409a9be632b550c26a1b22" },
                { "zh-CN", "b0095eb7edc3b11161f8677db0302b41e26b8e1a2a494c8ac32537ff4f71db3db7e9e139f2f82e1aaa172f656b6d53ead7fa89db09b99cbb9583275fa1c93df6" },
                { "zh-TW", "c920f998c2db14b60f976b693d1467f32aa543dea99299bd8b1f66664406399e7dd687f03412927083892e68b338413ff770fb29853f6c6d7e6239c0074444cd" }
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
