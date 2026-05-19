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
        private const string knownVersion = "140.11.0";


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
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.11.0esr/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "5cdecdb779fd9766b0e81fb7d481be0f409aaa0e5fea273da81b043cb3f21a1e904228c2172d74e0829b3311ccb6a5b552f0196e29b2e7f29c994c4740ecc7f9" },
                { "ar", "c5cbba3f4231e592456d69b6c0068a7666b3565f3e6a5c7764dd7faa7c45411462706498e1a3eb805120784c4df02e87eb7dc31325711aa17b18e92eb921470f" },
                { "ast", "ac44f7ab28511fb64b62c0fc8e37690b3928c40aaa3f9507165876c3147d98ce712a2501b71fef51c4c1aa5d59fcbf7e7939084bd5cbe8ed8ff8bf51946a3656" },
                { "be", "33a141c3db8f07b7c8153229b2c978837daff48b6315d3cd85142f95eff0459c6fe9ad564e35677cf022f7ee1456f0444cb6a8bf12d84268143a04fd0687a7cc" },
                { "bg", "d885b2328d68795604248b7264b00ae3eb4d1bb304a3643327b67f5989a445779fb4030872212785a070d5a45bd7d13949af8b5beb01d4aa8297a1a4376baeb6" },
                { "br", "107f26e71c19aa0be9f5f6218ebfd300f1c8a885d74d7dc7288b96be2ad5bd220edf3f2b18f5f8bdf24e425360b4448a2decc28554cba4b04be6fa5cce74697b" },
                { "ca", "6f38a8a0ce621f1de1906bfb1219aae20915d46a3044182d56c496d40a9fcb7e48d56020bfdebf8f7cee3b9a951108da151f0656612b690e8b882034dde1ff9c" },
                { "cak", "844e17373072baaa914b53a518a66dec5f5d419f372ff810694f48cdf26cbad313f5b6ac7d22a0e0a1d841fc13b6b109da6849d4bedbc8cc0e78e3119f1b1fae" },
                { "cs", "50bea8647d433963ad1f3f5bf19f16cd50fddc2abd3f22c535125a2ee24b9337fd7158f0f17192b3989143701e9932c9ca2139a9944d0597d9e00f484072a7d0" },
                { "cy", "8a6575987a20f2e840109d85c5107d662e0a52e24bf3b82ebad8f4082f0c8d8da6a2976aacc56acbdff675736e6457e24f7dfa24cb861c3e257ccc77d8305ab4" },
                { "da", "6076f30253ddbd38768b8771178e1e8d675f13f0a365b023b20600fcd90769c01baf8d5fc1cfa463ae78bd427e2c50be18e0f10f3e385ccff237287eafaf7715" },
                { "de", "2068c2852681eaff5c473d4211e406566633428bc4010ff6cd968ec305505ef7e20111f51311f548e25e12d58620f9f69c0bf0c198fe10bc2c5ea42587c459b5" },
                { "dsb", "bed4fefc8443046d9e6e99c50460a9a9177ac15dc1c3db81f7fc9ceb12cc3fe482ccf424525507ec679050b82b287e1dba644ddd66b5eb6b5ff9a10af0c52cb6" },
                { "el", "8f2224fab5fcf0c1b3bef05d816389c0974524da2ed73de2aa8fe2a280eab29b3e7496343e40a4a7df834e1bd68a5c6fd279c93ca57d75190e6dd6bec3db68d7" },
                { "en-CA", "a31feb06a8f3dbedd37afe3dbc635f5905746fe1222bb67af1ab820a4124150ff8bbcc73bbca29cc9266b26c1dc00a23edf5ed60b361f2a9029d9216818603f0" },
                { "en-GB", "4a32997ee433360df73cfae919583aa9dfb66045061c080b65910563960b02b4155bbb5d74d8d348b8af795b6bfab9d121c7580561e9416f54082343a86a5603" },
                { "en-US", "7ccb43587e176ce7bcc9a3f583a22f677d6e70f412dcacbebe9e38ca8f19c194a6780ee9bb20f4f8d9023f73628436711cd86233130e2f89ed8daa54b935b667" },
                { "es-AR", "27ec539b198b16d2aecfad974f87075a8eb34ec80a32eb61e7545564edc7efedc8a31f6c58e39126dfc0c4ee090c0ef1d7098eb0f547417fb27e91dc95a33358" },
                { "es-ES", "cf4e35ad9b9327d2e53a7a5ef6a4cd90ff3b004fb52ab6c72e6ee7724a9dfb90f358eb5b4214fed6d29bf5420ad2296fd248b33c50d822441d2908a1b8a5ac19" },
                { "es-MX", "53d9d30c8a5bec2e500526a47e10ab9bf0139f2caaba7e60360167d623d49aa279a6a5321c4583acdeeca90a33a41bd90745e8179a3b696f44c94a754c1ad546" },
                { "et", "440d38f0032e8644ff8f0a1451f8c399b7e48562a421524a7d1fc32aa9a2f5c4b5cc738add6bbe5b27bed51b761bf74b92c30a3b1551c43bcabf8404b68311d1" },
                { "eu", "703e3a10c5ac8ccaa4d0e7df19c0dd05501f236342321f667fd512ee6c94234c26dbc30165b53a1152342e4b0f443976d41d5f47d189e3f4090f293b4a842c98" },
                { "fi", "a17c0889b0943ee11d3f49a1cc73e904f4d2e7347db853b5894f6e096654e7f6a73afc8ba56af44c2d6ca5f56584854b9344dee209a71bd849c962b0f8cda7bd" },
                { "fr", "6ab833823b52409fd3b6aef99ce2ef493f2f7b4b11de982f345d00f4bc2a21d360bd78ba0878c1ef7a9032412cbf5f7a3abf06bf3ec80caaf5062e9474eb6104" },
                { "fy-NL", "a10b78181b6bee28897251924ca8af083418f66b3a919db0f592b75b6ef1696c41a2827355d8c1efed68463232450abe785f080ce386e647e52862e8ed88615d" },
                { "ga-IE", "93078626885284e5caec859f47484431d75a0badf4879fd2b15c3a97abcf9d99c3085ebb3476ff3cf45c4dfb80235345fabb1a2e2cc766f28c97a27c45bd23a8" },
                { "gd", "3f18ac03929265c8aa0c41e3da4f782576192b1d5aba6bebbf7e6b172c8131d13d240f6191638dc30e19a1da2f0adfff7a07b499a52787be353f8e4de3462643" },
                { "gl", "fa19f54cd1fd8b822baa4e1ff507c34bdadcbc0911dd318f9b1e4bb609c03c49dd2aec5485d0e7ed73c13588e0a91d8cf81fc522f1ee1ad981ed21bd94e92f07" },
                { "he", "72eb13d6342ec8989105947897f61b42581d89158edad8474249b1752d9ea1b2a9e2992d0c5c21d453bf1278a6a98da83d1ed1417289a5f6ae4901f1051733ba" },
                { "hr", "13426e106fdb30b3ec4d0c704316a4cf1e85d046c477daad3c7d38fd03f23dbdead48e60ed79e7714ccb72a0c1e71ed588182f86aa40eb0ab664ad8bddb15f30" },
                { "hsb", "3ebc686ac92cd7362bf9ce03f88f9a9bf6fb36e26712c7d88a5348e01c2997e648ba53e68b80136b71777f807bde9c9a816a8ed6e7e47cc56a4fafc17461d8d0" },
                { "hu", "f2039f10bd81a76b2d26a603edc1830cbab5e8e922bc8b01457be6cccfd1b2159a1fff40ce0afac4e5dff5edc2266aa14dde8c306b8e03a3f316358e4ac6257a" },
                { "hy-AM", "e1b5daee922f11c30f67605f803902ae96f47b194613b5dddadedfdd3812b850b68525b6ff93dfd7ffccc47543a20438d659d9f5b86b6095ccd11dd58f701a31" },
                { "id", "5349deafac39ce5b6ff98f9eef742209e7ebf88d5d8df841ec2082d1dd9562c7ba3e4e57ed192aac70e94e744820ae4f73f0f1efcae9794f57956033a5aefdf3" },
                { "is", "58dc1f827cdbd1a03f978b8a8e83f68be4e4c3e5611d2b59a1c168bb211222eced26d756c431986f78d62333e982de0ea04a753160cba517d3364c95f7d936ca" },
                { "it", "3de02724b820c9338c0fefec9bea771e4e2930d641375dd66f8403d6e1e38bb4950582729086edac5ceef646a537763d6542ff5348ba0c6ae36560223be64beb" },
                { "ja", "46030539b51fd8df4ddd19d6304b0e21dd9c8a7242a69f0651ca0e6cbb46070e6fb53919d9f4f7ba89568bacd9c54a5be416fbbcf6e876ec49d95bfae49b43ee" },
                { "ka", "0a798cade0614fb526d26c3d105c4f1cefccd7f8754b98ee9681f383721efc0fc437fc62626bf28353d113c92a24e4b5e384a8f073b804d2ff006756d6e1dcf3" },
                { "kab", "53bb1b07845af182dea0cd68511db3066f4e351c3150b489a4557ab4dff6dadcdceab260ec9b224dfa2e11eef4fa713f143590d7c99e16c88dfb84ef9f3b9240" },
                { "kk", "df14bc7ba7dc20c8163762c755e831c15bebba5da77b65aa55eafc1dca057045ad887a1ec36d61bb81385fdcc57cccec17ada88bd03003405ca1364fe973d2a4" },
                { "ko", "f193e6e7f2014fcfcebe996a457f778a5f78f3e903c12c3dce3d54ef9bc20f0a3b04a472d57e1a17001bdf904073dfe89ac9c3c7a7464e0c3ec19cf97cfc39a1" },
                { "lt", "f9ed853cd9e094d845156f99ee36f9cde33a55040806a6986fdb0b4b6eb8353cd3ab71113a98079f9afea80730a4ea1f59d6c747ea28e4abb4dccfd6a7f8f404" },
                { "lv", "4a1811adaa77632d4b43490c1107ff4d5e005cf267f9a4a6b8c547fb639fd5de8ad5c1014958cf365cd1f5cae7eee09218feae083f804d0b8b171e4ba9efaff0" },
                { "ms", "b95d0050843f652267aab3789b4b9bb0aaf2f2d8b8c63b59d87d94e7ef234e024fd2a4c13099dd85886aede94aad1f9758a26ad0eeb4c9c2d1b03d28ff9bab02" },
                { "nb-NO", "b07243bb48b3da29e13c5321b6c9395fa14e3037ea989661bf2630873a17373557ea03f39c6ad76fe21ece5e004e6f7d624594925da3382a9d6624120a8a5fb8" },
                { "nl", "c3d3dc99f2e6b2a027e5c9304b602b7db857faeeabdaf71c7c0b2b3daf23575dfb448a002e2543dcd0e3f7f2ed5cf2ef89857415af4e28dbd0289f4143b07f0c" },
                { "nn-NO", "18f1d78b0eb6eadf6a8ee0a1f3afbbabfe5a7ca16f79b089139297b4b7c6e804a3a6370b6200d75575f99e103e7825da9d3466ec15a757e9785a00bd6103baad" },
                { "pa-IN", "d3fb2c92d512ccfc45b6a41bc098196b18bd1fe9bd59086516b14e719bc485b50180abccec01b3761a2d65ee77baf0d33e1499b99604bb426e31d89746c7114d" },
                { "pl", "5f1990e939f285f690ec69777ea6b834f977ca5e461bf07a8abde9fcd65aabbb2950285af3153a3ea46a244c1e58fd10816388381ab0c81b5d400fbad2362c76" },
                { "pt-BR", "b51e7f4ea5ee9de6c2c34df428edfe30e7ceb801c942eb0e5dd424635d154eb5438f1e1d75b54c0abfdab823169983b55684f7c839a7271387d2c568ebdbeeb6" },
                { "pt-PT", "b6a287e08ee7932a344eb34224735c9466425de18a585f41530225a00195cac029319132c4b630d3afff3f8cbd4cbc839682263d95a2e56a1331567189065351" },
                { "rm", "7248f67e2ca7958d88f80343e19d97223d083cc199afad74af2cfd5a41ffab972e39e901bbc0d805131dbeda531b50861e3853abd28fe69d936a1e671f1b2865" },
                { "ro", "dd7ef7cbaee2e5f1381e4eb1dd216802c7444dc325a69b1f30061b341a3a65951367fd1edf56c528ca3a90751f6e0f22195005817e2520d5384cb395b39d0801" },
                { "ru", "1ab3688073713485bc5cf9bb94a7f8f321782e7b7a3c1a124cc1dad40e6645cc66100209f099256bb366cd73c6278b4e32c2e874ad07f7b20ccd81bd0e8ff631" },
                { "sk", "95573c7df7563f8f2370ef81098c0d67ae2bf5c7ec8874eca497f133b96a6dafc635069d0c403bbce7b4188715b73f752de71b81e40ac5b8493600cb159b95bb" },
                { "sl", "652474793f29a1326a11607de87b8b0d56b89cf67923a1fed4318a1e2b7075e12800978f0dd54c3bbae9f089a446d7dcf99f053407471a50bc6d8e6b329e9740" },
                { "sq", "9c33b8e83446f9b5981d8f65670838f1dacf7245c63560a74c800b8c64a9f73ad803f09cf2a4135bf0ca012dda2c89a899c6d3020e84fc922c541d14a5365208" },
                { "sr", "5c3dd3ff7c64fda3b05dff46d85ee9ea9ed7e4d7c15192c560f3432cd959a971b42de98e0bbf471942c4dd7a823f38ca4eb3746f2874b8f1f449c4814c73caef" },
                { "sv-SE", "fc06b6e6d7d4e24768f5f13593c6c679d43beb7af56d251afcb342c4a488a403f53c3cb05cf75917de19367d1b875a8b70f1acd5da2298c5c3304fb2465a4d7e" },
                { "th", "50d87354cbc771eb8006d658270d934dc9c22bb1c04d915aa4367aafa98bd419ee1b597d0b801e70e7b632dce59b1d068265f8f51bea178abf05617654517f9c" },
                { "tr", "b6218f69f1fd0273f4589d7edec32363eb5e8a5bf8a1228d418d3d6d2d5334119df584ff7003d3eb81059f8de7c9ec9d1ac2ad4003871d4a6b32b88892bbd7b6" },
                { "uk", "cfbe3d0794d257bf2714c81d8578a0b8be00f6ef390b5091078a00bdbe3bc956fb27124cfa81f46edbe75fe99a2faf4cb87fa91812938c09226f017a4b245e3b" },
                { "uz", "4e56fbf333af2792c1281bff0ab21534cd088c62b4cebfd49280428c442c33c7f2691a8603b0461e2c22d1ebf11dfa90272e832de53270992845eca4eb47ddc4" },
                { "vi", "a7a100410160fc11e8e76dc2ad6122906e01527eec98c9cfcfc096f51ae1dbf3ffc0e966160e3ad2d65b5fa2ece148d22892628f9608be21896042513db80f2d" },
                { "zh-CN", "6be9e70957d0026830b00bdd328ab0e478910165def251e2a5209f41ed3696c5f1080bf592c30172d96f6c6c9915c0e1a09f723048550c40b06510fb0d46397f" },
                { "zh-TW", "6e340a0c94606ffee4f97c0967dd15b58fe57baab1518534f0f72c44e13c1c67186c73a4b3778af81598f9026c275e9387ec478864915e412220346b33d7fc74" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64-bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/140.11.0esr/SHA512SUM
            return new Dictionary<string, string>(66)
            {
                { "af", "01eb801117d063ced6fce6a8e66be0e5642b89342a83b93ed2e01efb7794cfe0b545a913421ed9fe192a5fa2216ee7fd1a22b491cda580e4c0e839c5b9a29909" },
                { "ar", "e2071a9225b8386fad280d17f0ea3a07cd07db1b81f185d9756eab8aa87cfde7fdf558fc16680e2f6ef240a1b91926deea995848c4f21a68dcabf6323abc24f1" },
                { "ast", "34798d9be08166f15f971b9576941635d09afd51350e66039d7ee3a7f03bf6ca3754fa451ef2d468dfd1e87f60199376139f46152beeb049b78facedbbd32d0e" },
                { "be", "d217054ba9b35d83785e2c4d2783f2d5ce242ba4200f680aea69dc16df10ebd6831b6adba65e4b1a940623e416aa9c7d3cfa738efd90a9494784404712ec5b60" },
                { "bg", "434526af1fb6624611ddf0f24e1c33ab95281f855fe19e0f01076865c9a4eb1cc316a7ce2b77444ff3bd87fbeb0f3b0852ce3e585da4445ff7f8b0d494adc612" },
                { "br", "c792287e81441167f9694aa2e8576c913bbe3ac11876e1a1edea9bbe5ada18072dbd9e06cc88cf4daaf1ddbe03405ce4d1fe47989d3210f9d0ebcb7688fb4082" },
                { "ca", "9fa5cff465f58a292cf646ef9280f809abe83a9cac66a35bc44a205e85c8aa4eb7a1650304c8655dc8794015bbc7bb3b342aac9293dbca37410abad8ca86cb35" },
                { "cak", "bc591a60fabd250389fbd946486b929ab2fc894d71a7b5b6e159dd2729a5b2666dbc775385366b2293465ede3affad0d2b220f01f5c397feeb5a6e5402a82a0f" },
                { "cs", "52ae3aa3d2827a43786e6830c797c80d6fc58715abfb866662b4a7f8e001a8ecb318dc8c094c120feb389dd492e180f4e01167deb8f26e9dbcbca51d25d0e6df" },
                { "cy", "8502b5e431f4bffc9d784f615309ae5445d36af81507601a65dca65e9df7e27509758835a300e81011e63eeff7193498c06ecd4560e393d151564f9ed26d89b1" },
                { "da", "3b53234cbd16b822c7475bfe230923c96c73cef04bd4a9817c4e68f5f2fe21dfe36d7cb2d7671702f4ffa5322c83a0bca6e04ab459380db61d527bc34e4feb55" },
                { "de", "f17d3597f12dfe66692c046581e46bbcaa06e7a41a7ed0ffafe9565133e32d4cec9dae3d7d9c3ba7e76b251d99f97161c1b261c08df15be97c4e194f1b007f99" },
                { "dsb", "db3d1907c188c8abcb4ef610f7cad7e1501ed5c8e537b1ac9d148e823e587a40bc7775d2d922e15f4ca812ac019f585fe21720fc60a747656403fa8ca566e01b" },
                { "el", "d5266458f3eebe4f3cd79132bb4a3b4fff7fb1792751018bf423e5435a7b469f579e850c4912437925d889de8c603aa372e5f8ef18a945c615e65ce5b8101f9b" },
                { "en-CA", "63c7ca544b5d88e4fd85b29addf1f5c626b0a7af71441f8abfd34ac676b0361dacda4ffa4fdb1b984cc325d9bdae74d43c559cd5698ccf2d4c8eff3f11d96963" },
                { "en-GB", "c453bed7d77de32a2c56e3425a5cfcd37f4210a909b1ab5736fe8709f97ae577776ecb610db831f446a4c611fb811f624031e29188cdb2cd0a61a95b5e994694" },
                { "en-US", "6f7272ddfb3a225d069089638988933d3b607b947312d140b5df4c22b65c125c7d412ab5be0c2acbcdfd3e51fb3847a6fec43484bb4ee7e303875f9bfbf09f20" },
                { "es-AR", "1932a59cb0b42e5a4fed41a93fc79ee1a7b242a38a9d8a5c7639154a43f20d5ef9e554a46dfd3a3326f29408ce18fc2a0352688a7838266ede1e032cb704a732" },
                { "es-ES", "29f7cfe4b8e4302de39d9f0d8ddfe4f33d5afdcea7e55d201a4785794a69a037664a2004e2373e4f2061a6af831fa552d3803bf05d212ee9c4365dfa05083501" },
                { "es-MX", "24377b369c6e85e8822e3f468d6a59c6d0157d841e059863177110680424a935651fbd537727b42b22c2866cb1438a84d8ab9a2e169f4b0c64b1b3681f63874c" },
                { "et", "b7aa724e36969d6b8970b36471d674c1bd04498785782047e3cfb11fe31c3238faf20138097fb127ca682e7ce554fc8fc953bd7dd057089ff648a8b27f570362" },
                { "eu", "6108a86ccafc7eeec8f639bf10112c251bd97ebb417630bb522932f0718297336dc474dc980ecb5f45caeb5a9e1e5d78a451a329ca7b3f7fbd8d6ff8b3be1d6b" },
                { "fi", "f3acabbcec496c80efd1f1be552322b2ee06836ceb9e1477650eacdec311d4eb1e94aa50bb0be7759d700a206a9fc0152f97ebc3b0e6695cf6cf234644533fd0" },
                { "fr", "6ad9def991e8b50ed5550c8419d865595c18270495a1394d986207ad8f061e81d912bea5487d937f2ebaee3e161d986f093821ec71689ae062a28a9b026411cd" },
                { "fy-NL", "8b1f0b2885bccc7439e8a71e3f10cd18e38a953bf82d71a7ee745142042ef9c0e4e94f8792ba6ebbb3ec0e3378cad9395566208cdf7f95d14dc5099a45475cea" },
                { "ga-IE", "ac6cc6ad5b3d7c24f612fafc7d24c313984f649ea405d0e171a112cf472081a41f053cc5f61c0268756f5e630f669f93339638baa8954ce19178b5e59e4a12d5" },
                { "gd", "0591828f96e020ecdb8b8479b34fe28e5f9858ea4767e38656e82d3e07dd7fc21dfc7a97ffaa3099b8f248d4ed3b932e4c78638e7f5dc5d0ab46f29e37541341" },
                { "gl", "989358433d61b8a359fa9b7d341f785ef0e486804e5732f2b61ea44598e705e024c77d135a852b733f6285770ee7d83674e6e447acd80fce804a7d810da6f829" },
                { "he", "dd7b0d525228b510475c8121573c8706ee4ac23677921d38159f78a7d7d93f8136f31584055ffb2608863f70af2743044975d3836ad4aca0e8112a9071b3436e" },
                { "hr", "e2be372690350665ece637dbe69ac745cc9ac5e3600d250b46ce1883c06ea3432e57ddc357af7b2c51d5cb2768dd71dd387e4d1147052e489edebafa8b38b50b" },
                { "hsb", "3f09f6b255344c5de44c64d74566a5cc9063d8f29a8d626cb00c846600247da2e5ead631e8e0789e0bd7a8cec8b041c61899e2adc2d46ae18ce559bc382403af" },
                { "hu", "c085ce02742ea143274d8439dfbae2887c0171ebb450d61dba31e2971a5498e2be8d27045c5bd3354ae2685a1f17f20bdd0f2f77673f8049cebe2be5393a30e4" },
                { "hy-AM", "b3c82d6a26ff980465b60e9bcdea8e544c845868a115f843771964a53c5209e87966e6833f2bd75af22742337dfd5858ced6d6be3a6ad436a79ac8764a52c6ee" },
                { "id", "c2d96a19a3ec9122993a163f03236b32a33a3ed74536f2afa0a437361cd56a5d609bdc0a99c9855478c1152a2c55c015a504ee8823c55ab7ccf6bd6ff84b6d8d" },
                { "is", "e886afe1d6b35c78d301521c9e4f266dc6bd9ee7bbf445abc433d4a8c1d2007bdcf8ba4c8211a4738f1fb78ff9c4508256992fe2cd61eeb0bd0718660c756cd6" },
                { "it", "0d2d507ea748d8e70b0ce641bcf013ccdb11bb63dfbfb709438b9b28dcefc33d308ce6a876fc33c3e6d9ee6e90acc025e6fbb7acfe1b33b1679aab721a0ec918" },
                { "ja", "af0c7a3b71c2b83dde1db4b1d0eec17fa83ec355932d20f5d74dc367b2410cb571468aae613c22214e1fcbf8a1c095c0863edc8a86b5ae5c734dfb2694d05639" },
                { "ka", "3d948922a94d82e86183f5f0f832ea0b1ef59f53d0d3ac44fd60d73a81fa051298c0f70bacfb894287372f5175a569993de45a21f44144f2889ffa7a04bd532f" },
                { "kab", "b173b826a0814cfc4bab534ddee9baee73609cc8718c11324f19167b6e47c78bb173bd7e3207713ea1ce695121cd1e6e579483e2b2ed80e4f4532b14f0900d91" },
                { "kk", "052eb76711f1e3a8098943a194d96e3d09b7174aa4d904ea92a1ad60f42cd4935fb4dd5a0aad44bd5e72777578b7c6ff673dc0d9baac89b67be969d3b1b5416a" },
                { "ko", "b41639a21ad6fba0aab2ceb0932965ddc282953742c58c00eed0ed8a4caab8c14a834221e20e5e197fecc8a0f31620079d21eae0422483179a402ce34807b9e9" },
                { "lt", "4f90ef5b793a767c3eb2b2cd8e330da787ada45ced11fe3b2806340c7ffb8d9757302b5faebe992d7f1a02a61945046b0cb6727a579191dc5eb5bf04ee60d0de" },
                { "lv", "57f1d4ba1ca8e1bf05c2a483a4b76a9ae58f0c7f5dbe574b9c94e2e6521b3baa28e2629abdfb247e0064edea7ac72e500ecf2d0797b05a6b411b40abf1829bb7" },
                { "ms", "e59bcf60b85f35b2174c5800d1d71104e949c41720ff33ea05f70763bef95a303f0e6dbde1dc68b8f3cd1fffab03fe31e5c50ae74b00d3965541ff7bb9cededb" },
                { "nb-NO", "b0b70253f6e0821d88ae190c17623bfdba91af0b334bbd6ef3609a293ceaed7dad06fd8a1b30fab13fe4e8f8d2eeed9af60cae316cf6a10d56d5004d77428688" },
                { "nl", "a13f8f3722868d104df919a1718f78db868efb31a76dadf46d7f9bad0ad5ae101f993c4798c36317c682484c2cf53f50b03bdf69465319e1c11f5d2928df75dc" },
                { "nn-NO", "c594c7095d5988305b42e310fd978d26411213501f5c6508c943461af2c3d1be9d726bda8f63d52d14b6974c908e6d6c6be444833f128ece99c7845f3e460937" },
                { "pa-IN", "5b2562c9dacc40d44cb88f4d835b5aec6d4a73b22f4fb2c4a558f518305009489b5f95e01c6a2424619efb4b43b17370c3749c3f0f1b2c3d5c9e68127a9f1bf0" },
                { "pl", "7e4c96bc53f0bdf382f6cf534ee4ac7c0316e852844f0a2224874ed1c82780b518883f68f85cd4bbed67aa7307f122a671e1ad739ca1b461a42342a5ba53cd00" },
                { "pt-BR", "dceca9294754241ad2bbf09f74c7bb594f12540270434cfbc0e38c6b8d15ea19d26ef926dee771dc2fa183783e5fd032612a584dc9f91ad524871f695516c8f2" },
                { "pt-PT", "44831048028c6f6de8e2259c6e8bcdbe00147d6433cd1c3adde591088d69bbe2fd443a3d880c57bbd616b256815fe51225831a82a9fe4fe6c5b5295eb872d3d3" },
                { "rm", "bfcfa0049154d517a67ec123d1dfae25ec1847491d8bde4470beefb4b96437376a8d419722f3156e2f91922951e74ee645a0bc81530575b2c72b1bacb5d9e892" },
                { "ro", "bfb88de4de531057029b9ffc17168210ae579f610b863aa14c9193bd45c4ab048808370e85477c459f8129f4e0d64e37b13d3215ddd9adf4c732797e220b1778" },
                { "ru", "078bf1f4535b24fe6f704190db6df4acd9b54175374a5eac212e5b254192d26b6ca30d6b36ae2a368c76e4df9a7d13df2f8029a09c322b47bee55e123041a3ab" },
                { "sk", "0ff01689fab1d66b31a3a5d1a8a89e51111ed9bd5ee34c14ccc1542fdcfb83a43a55381487a71dc686ec668366b7370d176c46ff61c3a5618686251cdfe11484" },
                { "sl", "d98ca5ddfe4ebc3a67705bb943da48cca6cb3b38a8515d4a363e52dc314ed4cb6c6d16a0cbb93115fa764fd190f3c0d44b3903151ab34eaa835292fc6898502e" },
                { "sq", "c352260f154ac515db04ed9bd0ea910cfc5720f56cdbc42424f51b5ea4a401d11bbcee28ac150a5c9cf5002880871f6f8bdc937f5401ab59e0e4122ce782c6f7" },
                { "sr", "030ba5fbb1420f491f0c73d48790f99b96adcaea35bf20e254b6ce96051a07aed4a4f1ac05519921d77eb78ddf5a8e8684de7a21805f147b2f69c3fe75950ac5" },
                { "sv-SE", "473e9fcfd03e56781882309f518a52a8b54b0660f70415e202b8e8aad191bdeb09d9614640ed2369a62ae4d72a607aaf4206b9e0c84cd7d504c2b1caffc76f09" },
                { "th", "9a2e8e8f3094e81cff97e6e9fa2afebafbfbe803ebe7477e06a326c12f4f146ae39e4c654cc9ffd814811cc104de01419fd7fcedcdfd86092571aacdfef8e6a3" },
                { "tr", "a5e2d8e8396edc6da7237fe8451666774deae087ded318d4e2071390a5296f2e7c092e26ff8c2e0a5b14390036b64b4dc6abf91cd03c7c5cc8d3fdc52f32627d" },
                { "uk", "241c646615800f04aaefc5ffb115f12657a83ba46c1dcfda2007f5095d98936a3574878bb665f8a9d1989ae303c216564d1988a0d5ba68e7a39e040c06687039" },
                { "uz", "50cf4293f6c4b813ed7d344070816013896794a969fd63b106db9adfe33d2acebce05132a5c3d98d5538017ed6ba6cc95f93d69deac4773945e673e1bc6dd48d" },
                { "vi", "fe8ca3ccaa380dae561414d2dd7fb61e55048522da548c5ba943395c640f4c0627497c1aeda7e7866350029841b29e0fe0b1453d0f3c54502ef05820abbad700" },
                { "zh-CN", "35b19b9c442515113cb097f7ec7d3358bd216889c569b85983d5fc52e1a21c99d8e512ab900b04a585ec45e782489fab814a1bcd21ed6efe24e26544acdbb25b" },
                { "zh-TW", "8c15ede385cfc5e3043f233d0801bfcfe06b244a41802d78c30052a6e61bc64f9931e21b638bcf890f08d2c23d8dce5023a0199ce68bdb70ec7b8ec6254b41db" }
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
