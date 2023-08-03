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
            // https://ftp.mozilla.org/pub/firefox/releases/102.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "0adb8b166cf3af9efcaea97af57b374613b65fa8db10fc86036e09a2265194a906371b62299117a867fd31596afa0ac71c2d6b00b583e889bdc59638ad6543b7" },
                { "af", "6646404b9916093eecc0b118fbce622ca5e0e0167248662e931c4fa9035db0a40495a865d2a14e2387f01616278b22d56e4e6ec2ddb60ab8e6ec1c6d4e1bd9f9" },
                { "an", "efe0134e6b5605113c0305db269a23665b48cab88c02dda0ab16d62c4676df090cb637fa8f9513a452d10e315eba2218d2baa42ae09af543c1a6292676042a76" },
                { "ar", "77955aaf61fd30384b74170ea1aafb9c5145c32f643851656c7a285c14d745835e173d11182bd5ed1a56bf928899ecdd2b7882f44c9a696e656712361c428b3a" },
                { "ast", "20db9488b39548d243c3ffd78e62df490d810c9e8e830d5a4a1522018764d1947b79c7fe7fc0d33326ed7b239581c1c805c73bb5f2d6cf625a48e47f5bf7f1e7" },
                { "az", "b17b7ff79a8fee8cea618cf2fdcb15e333981aad6492057c2767f9567cdd70c8904a3fc2442b834826ade8b8079925df2d0f60ec76dda5eaf8960033223c9ad2" },
                { "be", "abbdfbf51f01f7b58d7d2f912c72bd948b138f30a612bcfb2702d4ff601d0c139685df14f19f293feba78ac77fc99478d097d2e3cae56b885620f93a9e8f54fa" },
                { "bg", "8ecd0defb1709861ebcb92042ddc07407ddb8420b12c241dec57e679daba80eaf0bd1ba4bd6ac54dcf7814982d483bdc4c4913baabe093f7b1bd51f577d4c3ce" },
                { "bn", "86ca5155157e48e91c9e2893fc8477093a96950381c0f3e0272e92b733e5b668e81adaeb654596554378fa99e7b43189b2b1159c0f6b9b00120ebaefa9fccff0" },
                { "br", "736c974f75a03b445675b3e3dbb9ce771fd088d1123ba6b2707a9832c9657da97090f2890709af1dcdfd028210cd0c695bf47af5c73906b66dc9fb5028c8df7c" },
                { "bs", "3921be8150cba9037f2fb4ffb9c1980ada688041202bd4c4ddf7ef7bf05fcb471406c0ca24e9e9f204960d8ff103805c1e1cabe9101d3862cd4a05b94af565d8" },
                { "ca", "313fc34200eb11dcdb9a08c4cc3bc30616f5a08e2904d72586855fb368abc1e8a498ef5e095bdb844b4c8b17985eb5579596226afae8b02ce9d38d7f93d7ab0f" },
                { "cak", "132b9aa792fea7718dd96f89396fff3bc1fb25989ab4cd60e58edb34f81129f29a88322b8638cee191c8c9eb1580e6e09625707d41de4cd488f9e8a18f02b100" },
                { "cs", "bcf3ec73f534c2cfba704659565d218c031f535753e95f9566f2909ccfb24a86dde048a03770c6b2cd24e38b65ffc13236298f87430271259a65c5ec7c5f5b84" },
                { "cy", "7f4630d2cc342290337b2c8c8f460ba1dc95cc35e371c38cca0956f7c48d6cc6be6808bda9f8a928a8538844ced0422eea5a1d11c04667d9bc77d3e05773d701" },
                { "da", "81b3263819c920b41f42c4c92fc0e36b8c4ca0b7c38400ffd64206caac744b231db96b6e2f0c2d90f63cd7fe7a3ece81e09c7cc2babb4ee331b03a687aa310c2" },
                { "de", "27f93185dfad976951f585145340d624a0877040f72933b2df84282a0345a8796a5381713b52743368b9e8e00266cd52ce53b26b8676d1dde0a0cbf857ddb917" },
                { "dsb", "d5a263ae5926dfc4eaa6f5d93f7d0a2729147ac12a0b403d6d4e70d2565e8f05867b971a071198cacf0fb60e0599f6db070c0df426f5d290b798909903e5abc0" },
                { "el", "bfdf63a64824411e7c9e469fd19d1d01dc6d1f56cd7091f8274227acf2d949248966c747e19f27404814546fc59b6ea0aea42d0b4cadadc6c4722882c629b3dd" },
                { "en-CA", "70ddd44a48100c241d9e28f345f5bb97ee4db0e5283cb1b545ec4547302fc4405df29383a468de429a3ee0a4a4c760696e569fd0168c2570231914edd47c8876" },
                { "en-GB", "9768c1f80157bd342b62a2e44e950b3bf0d301e533d4f91929f88b292ff9b0700f9e1431eb0594a41b372fe0032177a2b0c162654040ad8b5736dc94ad8994cc" },
                { "en-US", "2f3434ea70eae295191aa089ef04c964466f3d917da7fcd302356f6514e6f50c3991e3f114a70995daf7dbba872fe81a7f8af10877f8d766f7177cec08ca3928" },
                { "eo", "760e34f9130656d1e8c231125e96e1753556cfd11a3fcb0b5973a82c011abe60e36467cb5bcaa07874f9ce51a0873af838991237a754d3d6dd9284203d6463c6" },
                { "es-AR", "062a213766c47043e6feaf9d4f0437a03a4ed9ede02bac4c873c70f9574e3b196e4b73d87c2bb67be1d1e85abd1b4ff074d1da9310f7b8abf961f2efe889335f" },
                { "es-CL", "4e7ff97fa6cd4f0512769f7cbc5c915d9bc713447a3f5ee377a0b4b07f3a274a57006e4756212320274a7ae4eed69b66f59b18926a908ee3c5cfe9734304f4e7" },
                { "es-ES", "00c18b8da12cbef2529e8964fe63fdeb6941cd41556b97bbcf0e3011b12e2626d0fbf19706ca84549bb25b3bb4a5a4fa291767dd6286cb009c3263fb96315d5f" },
                { "es-MX", "ce46737320a48de61270c0af8c9abd0348d03578d4d93d25e0482f1b274cc0b335b68623326643c15cb153ca5fd38421b475b89dfc1d0b62588785928c116e91" },
                { "et", "884de7cb9be7f0ca1f2513f2dfd870ce5797d1e4689647abc32e90732b976e3b82537c6474b4fab89460ac363a7cdd3e940a50aeadc6afd3d2b35b927d4122e9" },
                { "eu", "8e2b2c0bbc24550d2d494f43cc10e7aa2822dbdb1b6e0f179e38716ea4b8015bcb92666d416ec8d5f406ea786f36663b249a041d3dc177ba144b40d3cc50ce1b" },
                { "fa", "51f0ec4a5d4238b8214a1a7b596384a365a689174a503db4ff4a5ac6ba64acd8b75ab443e61fc86e602e179893283b237933563b6870992e24f5c6a8032792d6" },
                { "ff", "1dee9575a02efeb7bcc92d2f0e93d17a37b16c83769601c38676a7213d8549d23e82c9300ff6ffff3ee3150429d9eee06810040cd62a5e4433bd699df47280fe" },
                { "fi", "4ba1166f7b46f8f7ac61c4a952d56ca2fa0f350e9fb349492949e8aae5e27a0330bf455615db75301d675d6cb61e3470d0883392656d1b8598a50f700452cfdb" },
                { "fr", "3567d1ad1eb6333fa34e703e8972074b8945d6dafb97bab9dcd933924aef6e2748eaf553d3730c430b51bf03dc5dfca1935f807b2d4204900d1ebac9817b40df" },
                { "fy-NL", "f739024aba55d7920fe80aa3c877b4ea9212a10d7ea85e773214f2176970de37a4bd685428c2b50f2096b579f512622b7d59e38cdb1087f486b475957f26ffbe" },
                { "ga-IE", "cef360bc6ee3b9142efe382151fadde4744394dddb76742f210ad974d7cefa02d13b1ec57d60db1efc0711f1317f53b62bb551d2daf4c376961c9922d8fce5b4" },
                { "gd", "e397efa277e5978718d6e6334abf8c01c883dd8ded2a40fc1a0b380d827c47781783e4a52de4bcdeb9c5fa86086ec3574dc82491c28b111422fdc4f47049cdc7" },
                { "gl", "fb57b710bf39772fc8e893a71887bb8c81be0a0c0d0e22c987ac52d5eecc01939e18a5e0add383c48d7f99cc44e0e952162d87a0fc5f59bb1ec2b06fbf186a32" },
                { "gn", "5eaa53fd4e1a07897472bdde831b5cb9a6bd264bf70f9c43afa32ae86f7ff51e47a99cf922f8641ad471a7e8994dfba979e92ae39c4228eeb8b8a26c2285f9ad" },
                { "gu-IN", "785fdc7f0204d5dff50349c318438eec1ad7189a4eff08a57847f80fb13470fef60f0b3bc27508f6415007b13ee7dcd48b30de26b3b962f3afeedee90e88062c" },
                { "he", "257a9aef247db656f3b39f5a8a576530db6c54c381147a19bb523b369ec2839f16bcab62dd8073585dbf153f51e6738dc50b40d8de75e7e412327a627608d506" },
                { "hi-IN", "da59f108698c7a5b8c60e5c4219e725cb549e83024028e53f27ca138bd3bdf6ace7cd59be8163af38b22f321166cb98c5bc01709dd6b425bf91f3fd6861305db" },
                { "hr", "5c38675bfc10e2a6498c09e8fb9e2133c22cd4849b9e71fc8ce1828e414388b6b793a419752537825e31676d3a1367890773be2dc17d2f60c63782eae6ead4d6" },
                { "hsb", "0a4f572e2e42f990b3c223bbc9b0b8e7d8bae92f23c39be26842a2617fc7d5d0c1f7e1fbaea933724f49a7b2f0e8a07d8ec39a6d82f47076a02e5636660b103d" },
                { "hu", "f431c91edfdbde4e7ff2e256a401e905a44eab0146ea883b7552150aa50866ebb5f7d7454400645bdbdca6b7674af038707303728bea82320b26cba4ef0a4564" },
                { "hy-AM", "fe9bdeb7c5664eed4b48b69e546bf41b206a54fda9d28ff5bfa39fcae36b9d4cb51392d885ab4afe029f4aef9dfb741d72548f8ce5c9411938ca3babdfcfe816" },
                { "ia", "9bc1bfe475b565b69c00f491e6f2f290e7f28f6230ed3c97e34a93c07831d795d5ba57c8906f48a1d02ee7640eb14518e0458efa11d4e57a64d69773a64d1f3b" },
                { "id", "e1ea30a9b5e112ff0dedcefcad68f17ffbe8e8e254a99d07b4ef1713abd9fcc5caecab25c9896fb466d641c12155f540b8fe4d77b27c8c34b9c37f74f1a51b63" },
                { "is", "7400a4fb9b214e4e2938821f599c4dbbfa062c94f91b22cbc83aa100ab4955514f8f0425ee63a3765e4554609206487bce698be05e48c071e556dd06d696e68b" },
                { "it", "0c12ebe65118e07cc5f051a007780d1385ec705e17a857bd13f09264e943c6a4fa15cdbd4ed0145543f497f69e170236729e74d90df29d7ee189006b6db5beb2" },
                { "ja", "31de93a9b92265ee3ce11759e9391ccfaac4ad6593fb961f6962e488aab3ce2b46a10c50dc591d7541e7043900b30fa00e2552eaf31b84c16451413578ca396f" },
                { "ka", "e51c0a14bdbe5fabc4631cc7c484a09bb4ad47ccdd0f566aa9590a4a80e9ef41340a28071df8f867ec0d3645f8320a168147df2d34ad84f56a75ca534454a589" },
                { "kab", "2691f300138b4f47add3305c56cbcf2920433db257f3740b2a6f6115c06e491491cc209dab297e226308ebbbf949d7e87f2454c0b68aa6eefdaef59f5b722953" },
                { "kk", "7157453ac932d2410c32fd063236546a1307cf476a35542d8b82369495cf8c560b0c541c58cdf26d889c24ede795c3427baf36bf23c5856eba2562d5f8e017d4" },
                { "km", "03c5f0bc270894d98a69f31c96d21157595ff2fc82dd44336f89079f0d1f7dd873ed741fb1bb331eb81cdfa4f08d8432e6c6fb7b4f84ffbe2f588c97924b6558" },
                { "kn", "bcf8ec26b11414e0aa9815fac851b4bc4d370a2892236c2f4594491e7f33569cb535f7d6f411cdd89385ee805280cdc54de67d707f0d7897da4bb1c292405fe4" },
                { "ko", "05a1eb8a272cbe5ccd15f16f44a5040da6820d250ec83ff16dd81f532407de543158afa3a22c6d4643a4b1f90650264fc46bcff1ed0c3f6d067097b5aa0e521f" },
                { "lij", "66557cb26f0fd457893da53ad818ecff4f0984fe8806078f2201c70bcb87443cc25d73d10a93d05ceff34323eac12bf00ca35c1f8c3e52ca3c8b50e370c31d24" },
                { "lt", "8c2362bcf30ebc6b786b67622b588bbafcf627546973b73e03c5d8fdfbdc558a61c05d79b1c1185e087554fae69a9a6d8ecdb8b3b20f200911f48256814e87d5" },
                { "lv", "984301c9ef6440ff3f89a5d5ce4aa16a61441266ae4fe9cd88dc49b60ff608ca8c622f7649db0f190161996c65e05df548475a0fc04ec6bd65919e42bcc3cb73" },
                { "mk", "000eefa71d7906cfe40c1f2412951f0d44b8da5e20219543805e009971fb1e0c1f581e55a39b71451f4fa6d3eb6ec9a6b16593463d574395a85eb8f0a3ae9438" },
                { "mr", "4eda1075370d16f846030f49c76eac6220bd7cd13bba7c7a1d33dd8244172e35984e53592c82f69fac1a45b0c09074f1a530aa0efdd0d8e65eba9993168f0b97" },
                { "ms", "3743892df4d30fa56aba321ffb1234cbca62648fb2521e276bb7c9352aa146917987ba75f7dd20d842dbae25623ba06510581271581b2327201100600b0e2ce3" },
                { "my", "9414c9e0070ea91c49686b2b3c0769c5741daab4cbbaf2bb397363303b02e5299d366144934303f4778ea1b6e45dcd1b9b1b7c4a135c5f55d7603811841b44d4" },
                { "nb-NO", "898133cf034ff8156c1cead2f9fec601eced5e566752582a724fc84272a42860ad37ee87d1c3e12996609affd2757cddc8c0fcf4f27d96f32fc7e64cd75751e8" },
                { "ne-NP", "ef9c61687149242ab4cc3d819a73ba0c7467cbf11d78368c3502558fa4b6e6236c338b8acd1407d1b073034907267924f0dc56643b86619fd8562703776ec0f0" },
                { "nl", "f8aa59c3bd464bf2b67910fa0d0a9eac3fe097fb18e4810aede57f7fa588a06faafb6f44436c01f636f7e01e587a02624f302cc566de7e197374683be7e71176" },
                { "nn-NO", "2387242263a6838f678f63d52d20b007d0ea5b667a635062ff8c49fc0fccbfbe09eab0ad3a3725e4276d0a73e01999a2eda5bbb4eabd842be0d82271937fdd01" },
                { "oc", "38c941ca2eeb6416a554f1b3f314a51fb65a89dcb035aab048f1a962308ec3c52fe883f89e192297f56e8058160e183e583d84ab0a5d3cc27a939964a67fa02e" },
                { "pa-IN", "789a86aa1ad49608a168e91514d3f67fd73ce3cb111531ec4dea89bf7b886a58b720b1471712e6ff01ca656d713422cab46ce4c3e62338e3f1fafa33bea7792b" },
                { "pl", "cf6d95c6e3d98bea50379820867b72e4a5d22f98bf24404c8594117d6b7de6bbef6eb088cec71ad02a745f4fb28984cc52d0f12c75141d74ab8a45b64ec28815" },
                { "pt-BR", "1e0980aa48f29ca76a92e445b90b66cc275ec33697aa698a3c7fc0558e704545128526c7702a4444d40e79c298eda202f5ad9a0ae01c4c80ff7aef30d3384ff0" },
                { "pt-PT", "8a6cea0f698827d85583ca43ccfaec38f4d0ebb1db103a746288653eb624e4de1da0c1c64747bf953c5d4cf01437dbd410f6c0668bf2a8dcdb4a2636993624f0" },
                { "rm", "a0d6c9667b1ca26b2b667b2c8b1530fa10925b6bd57e9499f97e01b76d76bacc71007470ebe6969b5e59a2cc241206bacd3afcac79780dba4baf1f636532f3d5" },
                { "ro", "5b9d84001125bc85fcaccde9ee1504e36fedb83aa4147cbde8ef867b3cab41492c8a5fc1d1e5ce0017fbe17f4eb8cfe380fe97b4cbcc8e0c89611711888fe9ac" },
                { "ru", "894c2d27a1f462dcafeec5e49b4ca5db63d34cd4929658ec49efcaf717f98bf193e30b363c53e56289f504c995a8352db3aeb92127d58a93b7bd0c3ed9f87220" },
                { "sco", "7e07be89f9df47a608714cc4a3d03d29660bc075180a685d0a49c17eab0538442ecf16fa5995919090adf96da5b344a2303f783979f6385b7efd3e42c90ae0d6" },
                { "si", "a999defae8218ce0dedd0930ed3f3540d57ef50995c3618777cd20a82a66df3da7d16f3549a652852b0a6594b78b3af7a7c0a719593994ed6a75802af05da9c9" },
                { "sk", "5ca4c6253a02acb15a317f39ea0a12320e6e2f09e5ac7d8c299ddddb9623c57f2c9192c98e8b363d61279ce98bc10d7b536e23a09919571e6452aa895ff7a0d6" },
                { "sl", "ade7ccb338e865272af1cf113c47e054490f4114fb1c2b929def7e6bede719ad457db79b6caf73df210188d3a4cc4d5d2fd3511a1e510d8bcf560fcd66b44552" },
                { "son", "e623493ae8c58ee4160cd9c96606d394e25e7b1a316febecc6119438110203cf056ce0082cef044f26b8da754d53ceac64d29723ce1dc8107843f4db54fb8502" },
                { "sq", "3929b90d3889e1c9b5d748bb83ed003c9ffa7a4454ea4626509081c9ff43499cbf88803b1cd9f6afbe61687d47e5ce1afbde40b6dd1d99b5655cb639a2db9f41" },
                { "sr", "d6e510ec9e7a6f1dc4ce59cb67486848236795e1727fb31b7e6d78fc5f3ba1fedf008ce38e7be70b00f9c35f42288cb6e99cdaf9a245514ae1bb39b36a2f7839" },
                { "sv-SE", "e3f83a6f4d4b56ad270bd05ba531b73c00622ee468910946eb6a9ca660927a6ac9f38353f1b988a72d005265086f3d69b8fd3dfb86cb4604d25bd7e2cfa3cf04" },
                { "szl", "ea6cb917d742754e041a01f973f0fbab9c6223f37eaa4a13a2a15de6f4f4b224d2112d784703ac9a0d311cd4a9a94a7152f1af30abe385645cde865dcacf827c" },
                { "ta", "768df202ea149bcea866c6995e12a2fa04762d72bbba28b2c793f44f5d78ae8ad6556bb5ae6317136e1e20297b35edb9115e8ba033ae25fe992b5589e364d369" },
                { "te", "3f7a145d8532a355ce1df7be38018ba79e584db6c7441ba4640d9b640adbd3f93d55cfe1178ea5c748767815bd98634abcf122b5ab01ab95d8047fac0b413432" },
                { "th", "e3b0d8d310d8b0eafd6396e84f537eef3efc799b37951b60b456c7bbde718e097f1a4f0b5c8ea5aae82f147488f7c1ee7bc8cab0252cf61cea011fa3e1fe6be1" },
                { "tl", "5e699229f19d273650f6335a50f15b70a521fda3d35e9992a0b56e1dc6c0007f00b095a34cda329ddc0b99c5f4a09faab69d727e37e371f9aabf8d31c9ae7e6e" },
                { "tr", "6f714df382bfa9a81d4d2579d3fef1a722c891540c7d4e45dfe3df6335001feb0c79532319f54374a0ecaa5f66507b946a7010e3949875e94c4f71ac89638a20" },
                { "trs", "e625d095cfb456836e3e1320bb27e908995e138c4056c3b933a192b228e1e3b1b1bf5fc105791a0110564fabd183c8ffa4394d1bb9493f65473467b21ced2b77" },
                { "uk", "88f15c13da65334832235a2243582e2c5df9e9f216b36c18e712e919ca8000193aa52f9ec3f0bd96b8c012917d9fec0e76e4176b532a4513d65d4252d82914f5" },
                { "ur", "2de20e1ff18ce68d7836ff34f6742e2674b8ecfc3b3695dbd0d228b47d087cd61e4ef4f05a1fe06a830199fd884ae4c6892d56ba64becebc5573990171bca6e4" },
                { "uz", "cdeaa6fb470d836b745a1d20a06cd6ba8eb6391b59a833806cb2ec8487705fb3ead56d7d16a8f3cf1c5428ba1ad8a9e2f4712a98046fd3fad06fbe08865839b4" },
                { "vi", "789e2d16e992356c0a468e52d19df934e7f778d3f0377d1ae830d2ab843c49ca0396213312cc3ff56d9864b7e8485e3efb99bb6eb5f63eb401bffaf1d7342b94" },
                { "xh", "4a8c2f72e8141ce1e31bdcd932e85e01c13190df086a3fe5b4c2789e534fc8d45bf45426111d8ab3c0bf6a2dd99930de98d6db430ccb3b27982793a520ddf6ff" },
                { "zh-CN", "816b1bb42b69f11674fa4d91a2b5df416ead12c951f406bcf0eebd813903e41ffdf54604a0fceb4825686a2719c3c34a770552f8f86202b30508d663fc073140" },
                { "zh-TW", "889046d17985377cb2e08a783636b3cabc8281399b21d21b9d085326001fd4e64491e08ecd8fbf6a0cb67cb5c2267455afac2e9d3adea5a1ad129c74b04e2d1f" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/102.14.0esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "2895673a2bc0abbcb560a833c15e52293897df116042fd18b7695d66c38aaf5f1c1904440f60aa6c784be3efc2423c110ff52c80bd89c06da40ea382ae318538" },
                { "af", "4b9e9d2bb699d448dfa0a095c03b70366216c9a74d353b4f0871070b696d781cead2fd83e2f8af5c7ce1e3a0a42ac74fbfc32ee97f8e2328f35baf4ae046ecbf" },
                { "an", "3e9af3182a6cc281bc7ee58b1d789d86ad8e620b8c0c22ac5b8c25e02f6028ec4baf8db4738f4128ff1bd306e88ffb4bf40939d2063e0dd6a32ca020c712d1dd" },
                { "ar", "4c71f39d84fde1a23abef66a913fd0813544164c8f6fdc5a3cd30214c58ada01851bd45c0690c248a281c8dd85c97b6d7743d4fce7ad2ea6f4285df963f47e1d" },
                { "ast", "81542f155e466a3b6926aed722f38dedbb615db6b5bb18511bc0216117697049baf4d88b77f2754cd8bd6a91ed71746699db0ce00767ddff75ffd5d4e6c80dea" },
                { "az", "241f7111fb7653b21f1061944b7ccc602b4fd0598cf4492efc85bcb067c5db87f856eafb33acb8fe337f0a4a0665fd56e97387df06f1270384f2fd7609d84e95" },
                { "be", "68556f4a0584d887b13fe38e2c54eeade92dc9f15f1e9cc64c10de9130d42fe7d7f3375c5f26827feea842784bd79fee168bdbdbd98e51d7e87cde30e601afb8" },
                { "bg", "754319fd0c5e25413b1e011443b6692d607f54bee57c195b4fb15c1bb5d920d143dd684c6a42581e0e0f96f6330905431ae12cb9b4ecb107551a832f3e32fa68" },
                { "bn", "4c74e3dcc2f8006e142116474a5340d3b3d0f2d4b678c374baff291c7c5bde889a7a8581bbb81e9038d1885149b975d2e6988098e174cda701cac53e9b11977e" },
                { "br", "2c459a83fdc31591bb59165efbe154c637163c9f125969b0a3773be2e7b9adcf5a9f1942c226f040391e15d2cecf9fb359e7c9d172f0a35d01b7d941d0a07179" },
                { "bs", "d18946c5d24705f77f54b5f4da6f2f4444d7200d3273675138b16b0ce0f6ac75c6b394f7457fd085211c5d435741bf188243fc4db4f2a367b5c3e08750ef8d35" },
                { "ca", "2d45b8763ea6ab9b39eed3ce4a42fecba1435fdc8472f0a637141c8fa1d956263b3a4e62fdf897934a72a0b9a3f12bbd7604780b020ecd0feb2d08e1867fb5be" },
                { "cak", "aae2c91ef0d63fbcc8734a0f4e10d5ab24e16011ee0017709379df490a5e2d764db5b1f2d494b08bbfd17086428e362f97e2785dd9a821c74c23cbb5e761ce28" },
                { "cs", "51d255675f9012be5eee80f4e15dd30ff80726e4e744fb9a4f8d30135baa9a92122a02f27192b2fd47a264b01bef677bc8b6bb518a463a3be0bf6f8007401475" },
                { "cy", "93db077bf63e83725a8f94624640d522e0843f17f52cdf4a1f36c4fdf217f49b44a6ed269f7d2bb7ff6cc9e46cd64546b7daf2b5dfe7068557f136d61d01a536" },
                { "da", "10f7d0de68bccf7a3c882504091e3ac22894c311a5f7311471a84218623ec62b396cbbbd8e60ff9120688ede7d60de52b6337fe67ac1653ba7aefad4f7c0eb29" },
                { "de", "d2a7040fdc18c5117ba73d6a7b58ca47d4e979d96194910446d36a68cb98b924a8d8bd11bedf069f1d7487759b5610a705441489cdc4c9cdd618265071cbd982" },
                { "dsb", "8a427c3aeb0698788ed47e2877b78dd957fae57489c3dbe1b41c3adcb07a502c9eb4a64fade0c11ac7cd067056695bd512cf0b29406515e614a29ae0df944095" },
                { "el", "53edfd92021545ed32e1c4ce11e58171d2fc1c6d18b28c0889b0dd1be36379529f07d68d306c6c5d1a961a2fdae3099712db9b5b1f5fbba799f6711971e7937e" },
                { "en-CA", "e9aab0bf8d6af7f75439b1ed7e54d470f8db09ec6840f806866b52f4751278dade017fcffbbee75e27114035e05ed3cf941c2327f2eafe75bf88d35781190727" },
                { "en-GB", "42be982bd11849709e3aa8689b6b22a14858f2cd6f13b04889716f94ce06991da7fc11ab8c2238a72bb490bd15ea5c52d084adda7e0f1db078cc00c0108dc32c" },
                { "en-US", "8669095c20b9243a014c9f2b4a08ec9a746a35f255ddcac0eacb5d0b1b6ba17e7d419eb3f6e4d2a7ba2baef87f4d0316a9952fac3aa09143d2e03b519e3730ef" },
                { "eo", "8e17c7d5e137baba488d31bd6adc33301d0a09ee13f0b9e605ff14360b73428c28abd3b33aaa206ce4785e936022b50c2021bbaddbace04bbd7f5ed5ce700dca" },
                { "es-AR", "b21f7b3d488af3f0db5cad49fe3fc853f53c06fe540537c8fbafd25e02408e2d57a70e921fb406edb8eacc25cc723a9d1a7e11e922efa76c9a94206e41c0602d" },
                { "es-CL", "4ef75b5aac690354a08833481564b28a5aa3585a1c2839bfceda13943388385c596f997c94310e6bb108dad2e6341d5291dd0d801c9a87e1c94b351dca61420b" },
                { "es-ES", "d1e62de35d93f5ec1c842ded20ea84c62319237987687d9919478b9fe2e6d4fed42d4cae2d1d574180879da43b2aafbe9de936feef0d38ae8d24a563cb657ddd" },
                { "es-MX", "30246dc2370427b9191156d95ff327455906a65f294ea4e52c392bac4ea269c057c41aeab002cbd1fa3513016611d791d6c87fa26dd2cd91ad4bac026f3a3679" },
                { "et", "a3423fbad5e112ee76807edb91842c36f108637eb42b442e93030d4974fc6767ba85edeeb34dc4c63335fec0e0c533ffeedc5faeb6820ab4d5410579349413ad" },
                { "eu", "993f3647dceea8226303bea31e6a33e4301926e4be79bd9d8371e5a246a29e11760f2dd35f0e43b705b8705ec5e0393ca07d0ef136e93e60b3c54ff96d6dc3dd" },
                { "fa", "7de1ed882c576151c46c26e043007ce055e1db89c900c29e59bd54cf2968b34b7839059471c34ed97bc61b53124838760228a7f13c9d5ef62f27c4ea939af7a4" },
                { "ff", "c8680706c73049f18ed03a9db187c786e86c71eaf8e0d1d1c2efd3f27627b12c0a6732bdb3654eeb694a2a032eaa4f9ee8eb5fb603d3ed31108f542ce0010d26" },
                { "fi", "62d33fa8b70277848fba200aaabe7a912793c571dc8174d028743aacd41503fd13273b5e316457ac8e52797a2910e5e3245bd7b5f60894df0640c89e70cb7a70" },
                { "fr", "f2de7cf1ff5b162e7ffc2e5d7cdc3b6992254e742ca9b8ee5a9dd634a04889f1d3c098f2fc8b189217db566da42650c208ac2432497bc7a939d40aa806564775" },
                { "fy-NL", "a0ea992f283814aee6d2c8b925e75a51b4b13fb2ec2414acb3263143ab1081fb8c1a95c43632644992d8d7908d679168ae9497e968e12a15df2de16f165feeab" },
                { "ga-IE", "eb54dee3460d6cdc712ca236497d2db4e0d10e425bfedca28c01ef429e9d88f63179f38fe89689412180960f8403942ff1a3d84228a880f8a05940ac8b74b5b9" },
                { "gd", "b00985d00f95f04635f8453788c4551cff089ef54a8bfab53838cbb464c4e02a631bce5c2556b52b62a7dae38977ea1eb5faf5d60d39ec6166ee7de560b39b94" },
                { "gl", "2820953e7970202a2f6342f128da608897fcb54338c18799b4560631d6f85d5da7bff9d0c2862fb18d8327833d1bc38c4bcfaa7d8864e0eac4cfe9d8e66077d6" },
                { "gn", "82b3100e4b1ea1b7aeb1f1b68105ec4ddbefc412ae2977397022ac1fcbeb3369334a7a75c002835c69288d934042f14e47a484ea3b533b3f7c06b1193315f47b" },
                { "gu-IN", "cdf21eb2488eec984ae807c53a20e9e9841e09b3c4706a7ee3ae7c7113b2da20062c9c3f30cfa76c318eb3a783d5d49097e221783fa5f1c117057a71061d08f5" },
                { "he", "f2521c868d58247895483bd293b1796cd51a0d77f3bc0bc123c86f1486f285160d86dfe40020a61573da3cb607bd22503a199cda3275f219fdccb299f2575f79" },
                { "hi-IN", "2b37f17540cf7530de12affd13a07d31137a54c5ddfa10ff9e04e89f23dc031f7510a7c00818ea75197469698606dd292486ffdf1041b522c8f56f66ec7273dc" },
                { "hr", "5bc34984021f71d6bc8cb407a9f0f3e92a3afb42d0da1277117c4aa2df86413d220641f80cab3941c5efda39a38b9789b5d21f7ba054af654dd11add8c7e1b5c" },
                { "hsb", "bebc65359062f672aa0d6b9bb1e5ae7d13035cd2fa7c04bd6cc98ea276ff465508437e9ebad5597c51eae63c4479726102026a33054ad261aebf3a87a1f91f77" },
                { "hu", "7d24402bb01a42a8985efb5d1497fbaeea51b82dac01f52257fcbbc92cb91545bdd493135da804291c5e65e1a3d67a4e09694a6b21e298429b933e6ff4a8e399" },
                { "hy-AM", "ec606cae62451884911a49ca0ebced5b8b86c0a01bc34a90dab009fc3336dc6fef3e17d37f502f3e8e427380b2776fb118a07c2249ea561fee9941eefa5e94ea" },
                { "ia", "589c809da0114d20e127e8d5dedc145abcff8efb6a753655392c17461d4659cc3439528c40271f966b33f22e64f12654dfe6ea5081dd315c042519f37717ad8f" },
                { "id", "7308dcc170517a164b8711bfa6e13d727bceecde7bb04e895d4f5d849ab7fc613bedfd778b92844d62fc3cb4a249882f27d1a8db0e98e5d5c17b795328e34e85" },
                { "is", "4ca4d1a324caf5e9b6a1693e9a61654a42fa7124c2587b60d994355f1ee218b032bd5423f9b234d17fe243b22c4a5173bcd42a9135d5013817b60e7e0ee762b7" },
                { "it", "0d5c120b7e33d7dcfdc67d6669da897eea76295c620f115ddc85d058cbf2199106a03a50ee88ff530e7a52fdaae5fefe561f8d33ee1e9a30f224ff0b76082853" },
                { "ja", "8edfddaa963795216929ddd66fe61c3e017c622f81e56020e56b133e9862f46aa75e79e0413c6dba9361e27702a58f6158db85bde85151f6fb33fc4574675a84" },
                { "ka", "b5b3db2b0921a9513a954d5e716e5809ec90b0810980ce87edf621fd32ed68d94ee160a07c6d88862e8440d2433e9d7095d5310ca713d67281de7c6903cefc6a" },
                { "kab", "6a9851e9cf50aae216c41b367d20733bb207fc28b18ab5549067dc6a01a3ecb80e18846f3b35b5a712b9253eed98f7f47f96674a60e70da03d30a55c29b58941" },
                { "kk", "5b4f76bf5a10da75c4a270aaa76da77f3491f1994ea41b2b36b8dde8d477999c6e0417b434e247d639762e39686aab9565caf519dd73e8e87e8ce3ffebb678bc" },
                { "km", "d43c6fd9ebdc2274b04532268f8f3a860eb264d56b6daf1e5838bd51fe84258815925745124327bd67bcbc840765c1ccd57e281f8e6e36e240ce7cffcb20dfb9" },
                { "kn", "660fa125fad28438da909b5ff89cbd5cc014453e34d26ef009760cccf37ed22a1a0a0c427e4d8874aaca470195d4c4af0a5d1b7648e2ecf51c0e6d98e8a65879" },
                { "ko", "538c0e4f7714734d17e085f16abb081c78adc84e51fc954b65fbcc104e7972d2c88c23194df949011ddda3e7d900f630fd20212b598b83c8e686c24d5929e725" },
                { "lij", "f44307a89c24ce5ebb0a6798641041c1e3fda70ec6ffbd4642334b9eed8b65da1f787cbc944c19b2a0338a0c6e0a3346d123e60f91b187474467d036e40b64c9" },
                { "lt", "b98f753978fde29b35cad90e704aca92f3741e497561bc25fef3bc8110830422999d381a4b69f000a331603c4fa8c5ea7435eec3ec42e97a71eae11b44f70945" },
                { "lv", "768a42954429305ebdb2c34579dd972d8e6a532b00b020093c3044891ef33378af2be95fc9f712a8f6bb394cb96fba253d6c08b3b40c6f8ecbd84be1eab21c83" },
                { "mk", "02989d3223307753a6a13b7e2f6b1d19529655be66a34a448fbad9ea9eab3bc191e1e5c5302874ba149b5fb6e9e3175d2c96dacc09edacf930f9122afdc37179" },
                { "mr", "d5c18c8bcde98a2801b7ae64f990aa94cb7305e2a60ccadcf9841e6aae21af376204b3ccaa1ee501e225c7d533e101e8f7e47400bc019d223a30b13d3eccb823" },
                { "ms", "5d085539219d6647155b8ce9d9c31df23143b825895d5c135cee5bc34261d420fb20923ac44f64ead9bacac4d6aff451eec198deda9233e8870a6a5335b8feaa" },
                { "my", "d798507c372203f1d172e8f6206d430af569ba6f132e76f5f85411218d833d277542b77a6681db9be2922b30cd51aedba66cce73a68a3bc80f81a87d81ddf438" },
                { "nb-NO", "b6cb0379db10529681369f77a1cada39b740a0ad7dc823655f24002a24fed5ac75438bc16f823d096c72aa80f798d323f553370ce171279088131709bae2f42b" },
                { "ne-NP", "8f7e88d5fd8f6a5e562b069e7bb450a7a7ba63506157c83908bb4fb3d20b6832016a25dd9ed543ab47179984cb10d9e695b010a5d6b9f52d8c57ba10e129bb6f" },
                { "nl", "15b320b2f3760c9edd90231a7a181bf83754454e1cb5e8703603d9c6a28c06fb131f81ae3c0e71c0bfe74e3f802ddb9ae742eb4a353cef3a75554c9d017e505d" },
                { "nn-NO", "4fc1f9b1ec18293e77432f8fb4739807ceea15aebfde5112d4c185222e305c1186a39eb2ae277e0b39d0142cd73767e8cccfbcc046c51533bf61878ed854a7bb" },
                { "oc", "0e0043e0a85c4430b0a7e1967404fb528d83a510d5c1d21b0bf42e2cdd3ea1c84cd36533fb970094fa524f0d568ee098d3e8fa8d27a9f77b7c9c6225f4854dfb" },
                { "pa-IN", "a842bf10ece1d36aa615290a7b99b9fea686c24f2a2c210d1d5baf6f3f99336f33ac65c68c355c12c5efc169e28015cb85d576bc7bf628a620037479a2c0448c" },
                { "pl", "f2a9fefac43dea14fe538b7c7d07f35f3494960d27b2d4e3611b43fcf503a120fcac60735b3b0b2bd8be9676ebd747a5cb95eb45fa07ebb8d90eb6cbaa45b0aa" },
                { "pt-BR", "99d67d0d8e669e6ebcae68694d1241c9e31e6480bb1cd2a0cec2e43833016110196d92719ddc78aaafd38fd886808ee245898239e74d97516c343f219d323376" },
                { "pt-PT", "b4b4ce1a3e8713a68e8dff2ed6a1c2a6e76c0d5aa58d891b3d3be08ae7e6753b326603f35cf648585ecfadb85a12f41b5e23fbbdf719265d2ed962eb30064aec" },
                { "rm", "491574a5d84462773bb0e888c0b0bae80ef4b7a39aae7b17bda87375cc00a34f74a6ffb4df9dc1b4865762a1678658f5cc86dfbdd8b3d6f69251503de468c289" },
                { "ro", "3fc7609f1b1673308012172643779e8d2322457491ae83730ff9c61551c2623d73b10d5919e49d16688f53f6ca664057ab5afd4f796e9d431b3e062f222196c3" },
                { "ru", "53b4a1b7244a17f8568e1dc5b565d32838d4d4951d4bc6fbce4a755ae98ff8b25022cf2e89c2af306249fa7f002adb5830a8f619e038644583f13e2c1eb6b2c3" },
                { "sco", "ed2ff0382d52e950eb888c2b76a737e290005509672deaa1b7e47fbad5c99abc12aff400776499ac948c4d4cee83ecb274b90a261cf152c0c12d3be77e44c5a5" },
                { "si", "78f04e21307905f145667f4d6e856a43862810154beef2895388fc726b23a887050c059778edaaf905cf836f92c96895f8354be20944b892c0172493a75fbfab" },
                { "sk", "0ea399a48ba9e1f3b62ec8181bbb239dc4ff01ecb2e0fd0bc4bd55f76e9d92ebfad2f264223adc57ff1d53a363c93d339ef4aea3a82ce6fa2879bd61da2629cd" },
                { "sl", "c107ec5f86f202b69310cec3f61af8632d625d6f1501641601646e7e40d9cb3bdd303763865a512c7dfdb98565bfd300476e17dba876e64114aa7c26149d3878" },
                { "son", "ff828e2ba4154fc5d125b1230aedda1adbb78b894b15977282a940d7d2a1b3b7247a5b1d60917fedca6e5af16cfe15fb98f6114b56f78ef90efc1e9c6c8c3de9" },
                { "sq", "89a4a4fae6e310ee984a9c374055a11c5c79bfee3832aa30c980e40e6162c222431115dae55bb56dcbbe943691a7000debb03e862a584577036b8de08e3412a5" },
                { "sr", "ee551c9c71f9df34f8629310d27962bc4a5ceafefa3c9e6966e6d1be0e65b0a26a21c46ee21b3b77e1c8a8ff4158d6a4ba805d5cc321337c4cd3737bf2430b0e" },
                { "sv-SE", "05e25bfc313a08478feeb6f4778f6e1836cd959c0913549b4b25b5e0667e0e35449be7a9e29940476319f16a1ff27fa6cd7065dd754e7acabbe724c7d72c7796" },
                { "szl", "fb48e143d670475ba973fe67672ea25d032292c7575c23aab79756ebebf536e0f09a586ce341932cc687721c92e2c6c558b9715aa6ac349af6645c44127ba012" },
                { "ta", "6df1aa92c9e98a513ec3be88608a47a22d11ec937b9e52cef42185ed9ca178abea9924eaa9b9b7965e4fb449126c680c0b1315a84cff8e7987c806940669bce6" },
                { "te", "1d68a76deb58408496f84308933ec4f28c0a9f881b6fe078b848ead993f7d49be35992760c22ab7986d423ea2dc0cfd940537d8910fa5998981f1d5148796a74" },
                { "th", "9e4e83d5990b08a0faaf18214b6907dd2c53fc604ce3685adb293f0962c0955067922ac5fbb2c855bfce8eba2db7787bac636e9adb22582c82c934f0824a5023" },
                { "tl", "8ad15a7ce11ca80fe52dfe6a49aca579f102352e1a7e031049995471ad3e07b78fe1a64afde1f8df9df28d13b8fe977f489a48087c2d5463d3e9d38ff3d96a94" },
                { "tr", "5eebbb9d81d289657206b91b6a2eccd637b5d4d1f1285d942e270910512d90ea97da60132ec46a2b2cbc7df24925602dd73ae45fefb9ba46575bf43e891f43d9" },
                { "trs", "ee8dabbb2804e58c6d8f4cec7f0deca1d78e28351e2ac00aa437f3d8ee3a10acb37812429822d7cd2444f3f34dde488b3aee5d7a3979889bdb045881a8c737b9" },
                { "uk", "9812a87399231cf3f39da36b319ad1b73975194b8b64fb9b57bdfe7d3edf95987bb274ab779f7bfd38f4771b6fe5f67140041c18484de0c351914b505de18500" },
                { "ur", "8d047831f134d4d565e32f687e4cbcf257b18115646cad3cfe678d6acbd8f50d87a711044923cc6b73d5ba4c4fa12c1240a6316db0b6d6b50e0ad80b8dfaf9ee" },
                { "uz", "81a6af830c64cddc5f1bd26d0614c7764f4ee9d8155f6a269403b28eaa3e632b03ff23dd4e2c69d614116e762004219f948e208e1242acd0c9652899e2290bb0" },
                { "vi", "7ea3fcf9c0b80a21864cc3f1331a784ce848a1cb58083bbeb67587c857dfe5615f5c6a36ad6a408bcb7a8d3efb126e6f388cd2cb3dbc591ffece33db0e6d3ce9" },
                { "xh", "87a8630ba43c82056f2bb6b3d8eb640663515808429092ee50d445516dff45315ac30d68d4e92971e22abae7f1951cbf7fad40e919db23f5bd84876b817b3eca" },
                { "zh-CN", "68881d1c23564eb34e4db93dbefccf6b2ffa8a138f9588ea4bbd3c9bd5ca99d741ae2ed90cd1ea253c98fc5722e0ebc0ea8465e50640df0a32d382af9ace64ad" },
                { "zh-TW", "af24b4e86b9eb015dd29ae31cb405c435ab1eb3a80d16fd5bfe20e0f7cd94e965bbdaad244909f5928a25794d5f10cfed93ddf7e528dd03a95fd8dca0f6726ed" }
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
            const string knownVersion = "102.14.0";
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
