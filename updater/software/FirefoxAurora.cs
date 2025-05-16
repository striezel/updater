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
        private const string currentVersion = "139.0b9";


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
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "6e0f301a1dcafa3751b7fbce79bd366afbdf65c172f4c09314a2962066cfe352db276bdd93b54c263204758f7b86fca39f236d911a069f5459e734c26b3a8b9d" },
                { "af", "30cd3e0d6fbe1aba06a12f0eae292f50755f9a199299af3f08c184d36e208aae2142befd6716e43f193a06f604132a379baf2c6af8c3a34a9b6ac5c303cf3557" },
                { "an", "2cde22affd590365ba77e90c62e76eb43eff836803a2c16fcc45dd42ca1b6121b5888572c42556c36e509100ec0e46258e5961e2a0dd1cf7eb1d3927b7f96999" },
                { "ar", "4d4122a2e88dfb5438580fbdca2fbd58912feed6f2172f001050e248bc3922233154583e31094ed3b71f69f2fe41627bf8db01bcfae1a0466a2ad1e1e3404bd8" },
                { "ast", "f6e077bbea79dec68f349496c9838c7a0060b624e079bada6a99dd73aed7eba08a1d1ca83a581ae3a01fc0daab70cc493fd1c0f01fa9cd32f17249d8aba801ce" },
                { "az", "63ad2349fb9aa7209c5ec70bd632c761b14bd319f0a2b0d60d008b122e18b4e892ed3fe26a215588b073ff230fcc3075671718db271419af1c2918af15de8edd" },
                { "be", "8b34a0ab532c3ccb9a45d79010aaabc936ffea72fb4f2ff5a890c1c65996e57bfce905e36bdf44dfacb20ce8402d34bb37cf6c5a1b46597a2f0041be31efc9de" },
                { "bg", "4922533a1a4f62161ced183f8936951259a3e7a5844d1e334f57b31ff1cdbc0246127a58d47a579883df57a9584dd971d50575c3e5127aed2f07fb566cf719df" },
                { "bn", "c90eea6d6ecd28b8b0110a4a9cbc76c07373047f919b1bff7c66782890224e210e09b066a9750aa04ad781ec6fee34f3032e5ba2179af3e3324d33f486816427" },
                { "br", "83b68d6e14e51d3057c153d6226897d2cba8332fc3b85270b90c187a947b5c87113f32d38c3b3824241efcfe8fa43e289aeb8c560fb98a5c41d195d367eb003a" },
                { "bs", "2fab1866f978ca3b1c2c4661b5811ad3917ea32ff54c3e85b2c99f8c0571214bce55278ae36301b1c563af7e3756829904663ed9afa927f6f68e75c51014df4f" },
                { "ca", "7517bd131823876be85d43a6fffd85ffd0b63fb210972dbaad39f99791ae6d8baf06269ddd02a955f509e26eb928795a80faf60de62df5bae020af24290c2f8d" },
                { "cak", "9b0759778fe498ab098c7b31b43a7de89a3228c3a580c2302a5c103dbe3ce3d5babf044473aea0366db2b1e8d11b2f9edf6a64da6c59e2fe2f9b39b8ddbd2eed" },
                { "cs", "71e27dfa4375c719b966c718378e1a17ea3b036fde5a7eb0a9696ac70b19a2b0dacdfc0e219a390536d1fb9d28b578ecf999becc45ab234fd376003a0466e75f" },
                { "cy", "07cdf51c09f701e1caf37f8127c62f5d461b721021b147e85bd2d81265bfba2d7be7d3e2cbb4d238a3152468d864a5025b5a84f72817797c770351816168c461" },
                { "da", "1bf19ae5b6d0630acb55bb5951fd73cfe369fbdd1adc7a747da97d495f7aec7063b6a43abd4a173db902f36f96c1f4178041a2a5dd159e958d939635da95d04c" },
                { "de", "dcdf4f9f72450ee235684908cf10e46538d9cd99be6c7d997682cf42565b2fe60a2301cc4c44ec94757e71d0a7aec41863f1a85ce94045bccd52a10237e58137" },
                { "dsb", "f4a365d53207d517c6221d7575a88b897fcc03a4e9cd9e5c982668d84071205ea8da8d9b974eed2833fbea42226ce6bf1825334ff2d30e2d4e0c28483005e20f" },
                { "el", "73b43b804baccbad3696ca2a0ffa37de17131357ced65764edab3f70243c79fa16ae4cb1d7f3a2566019a35b7b9e49cdad167978c885b781fa39f12d9d280555" },
                { "en-CA", "4a6305908655de42a271d225b89ce783bc4ffd760ac76e707392fdd2afe58704fd36d967108e55811fad3dcc3345b78c1ea54311390d382846cdda92d49e648f" },
                { "en-GB", "6ef4a09b1f59efbf6b88dbeac869567fa9a727f2cb3e2b6aac62a6ffd5242ffbac778093ce6e32e446b122e2e55aa48bc663520f42ccba088d172b7b6d2c9f81" },
                { "en-US", "b57326f4679f556db9241eb80d3354df92b83bba297ace9d70b7e11d738b23d7167dcf326eec2d001b4db77fe1979baceb5cd6fa6e602239a0120e2221664670" },
                { "eo", "6924bf3622ed2fe9fd88b05115ed920397b1d9934dd2aa3dfddf1556069cf3a5558b7a02e1e91f6def6aea11a0cec0b59731ec36b3078a451ea9517103305824" },
                { "es-AR", "a5d76a8dd3a21ab2f0d3e699482c6012dcadefe2bb0ae07c70be7cf4294ab87c479270e38f7a8fff1e3c77f4dca37524d7b7526c6e8c5d577b08d7c5e3207c72" },
                { "es-CL", "e54c56222fbab917e6a0282e01488f946055026476082daf2dca7fe54868522ad3771378ce68d7330b07ce546b1ceeef1ad581e06a581d758cb49f54ad9459c3" },
                { "es-ES", "101016e97c7fe88eb2171c2d187b002b255763f88fe275ca6ddef3d952c012da17d9aabe3981d1416cfbabc1f3985a166c504ce0829cbde79aa8ad560fceddc9" },
                { "es-MX", "c9e87e4fead7b76469f6864c8c7ee0fd06987848d4d42a21164410029d8a269ca5a42bb25b6c3485e8665c5d240b6b9663d31891674968b218b6190dbcfaf9c0" },
                { "et", "3517593ad5ce7cf0fe13224443e5db18884f80926fccbdd272788e7ec4accc8fe7091628c10c62494903c7a45c5b07ee35438f36ff8b21da8bf587c6da5d780b" },
                { "eu", "1009917b0d2d92397c2521718020a0e8614a85ea5e654890092946a7ba8a448281f9f8d426ac9ad5c1ddcc153cc95a08778071e15feca07ad982d10052b61a28" },
                { "fa", "428b7c42b99ab376228a23d57e5f669e2db39b7c70ff76222a8e732af613f03debbf29666dbfa33c11bbf52c194530c26a7a66ee7f90764dd8fe028e8149fde3" },
                { "ff", "b3b50ac08fb3df2d4a643cdc17ab5f18d14e1f41fc0fd36288d3dd7346b11bc071a396cff527a1403fa57c17836b86109a8046ca493716864b295e739efb458b" },
                { "fi", "6b788a762844906283b7b7a9e71dce924b22f431242feeb54a8ef72ff141272a4096d17fb588d58f56cf1f7083a5ae51e148a9d4421dab3f64e40adfddd6d8e9" },
                { "fr", "b6c80c8eeca4e9ff3fe720137a819430834850ca9a7731eddb62b89812008a7e4680dac2147e55304aef3db154b9a02ba0952f685e5611f384d4e6bdfd752b06" },
                { "fur", "2720a085753a9e4e0e7d0df149925b7d2e1de80b7a1b5fc0fa65ea2c7c7ccfacf07d1e2f8fc6848404c6b0314ff148588c6e17f0e0f617f97f87df767fa6155a" },
                { "fy-NL", "a2e9106325a31a9f7221bc70b4bc4465463d7bd774de00a095f7f23d639b040f2dbc3260f00fabe16646712726804146808a69bee8b62e31d967d9bd3c2a24e2" },
                { "ga-IE", "0791a0223a0f00bd02fc7b5f2e25c2b8459e80d503083bde1e51c11a9f4c2f5aaa442513040e1d51333b3d6191cbb4d962081003788961628047ccfbea92c49f" },
                { "gd", "e592938bba141647788aeb7dd62a5ebf4eadfe1c3af4c4db418bb3d1c1e1451864dee7794e6595b5f3714cde3d4a23c67fed5d9cdaef09a902877f6171e7289a" },
                { "gl", "425a0fb7d5104c8ca07cd63db2540236c994f700fd7d703f4f131e392dca8448432d51153cda61496441a68918523f581a9a73b7d358ccbdfe34903c09811d96" },
                { "gn", "3c053f7ea99f3a829334d4e5c9d420854d1c331f59777fbba4afdb561800b83c0505124e8b359762e58458714751d4ed00ea4eaca332a702fd6b89502ff6dd61" },
                { "gu-IN", "f2b12d17d2a2003d83966d2d86211ae5c7424db4478f56b4f5a3e685614c89c31d860988b414ca0e66f395297aaed4a73f665e0f5d7c2c83367b5017fcf0aac2" },
                { "he", "1ccebdddb315f0253a467352ecf9876a5b95d632f4ebf82a00bc94f3f12afbdb5a39b5e386dc47c2d1e3c72032536462723f40721c10304f5cad1d710ac327f5" },
                { "hi-IN", "b0312ce5f477ad7e12bf595630eb7f3721ca297a33e794a9435542110e196e5ea83de4113a2fd21ae54397e51211f35be907d10e673e628d3b182a323a6856a5" },
                { "hr", "24a218a7e994803a11f8d966600c51830c92db4b27c317315694b02e8e6f41dac9f93dc4eefbd477ed56d756e9598206b6d8b45f10095cef8f4b7568d32ba15c" },
                { "hsb", "c565cfd786d6cfc9407c19e7913f9b609c8ac085db3688635cb3399bfa850c344c715cfde828e62b7fa071833b1ef73061361bee1e89c0db24b51370ac29d5e0" },
                { "hu", "d81994815595f546ec389fac31ddf9f023d5f18c25068e6a3f38f8b4b1a74d934eafee66834560cdba54de00312268f159ef38e1352c19a8e7516a41762a80d5" },
                { "hy-AM", "04d12b4f494e26161e0ce5a0920cda33296505b31db33e71ae90d49946bf0f42119d3e0b50192dd45915a74e893692339fba31adc77e52ab3864a7491297d292" },
                { "ia", "56602ca22c35b467b713250933bf2a5cc69f56a410977c5655158356b8ccee28782bc6c41a601b40771833cfadeead500768532b279c36e65f6156df04d5398e" },
                { "id", "eb630d478a779c14d9437f354241ce11e08dd172e6ea5c1fa5ab53b278b73bf4f2ee1c07f48546602c90f38833a25de80371cab7176c2c3fe5d54935016fde6d" },
                { "is", "03483d70cbfe9c377ba980451da545ef496330f61ccaa6603d80633b23531cb8518b8ee63f7594a986d6da07b1c32ec3567b87f43c2450e657525c539ca4f4f0" },
                { "it", "1d44a86ca273034a79ab6e59a9f313cf8bbfc978591c07b69adaf93a6ec6da76d4201513703ae4e6bd1007bf8eef3f14fb0389debb34e739b72be7d0a40c953c" },
                { "ja", "5ce84ea987c8836a822179265c020a119d84a2b17dff4905ae23ace47328bda964b67be59562eb3a410f2c3c96515a95b54c36a60a6f7f815c007bbb0d4784dc" },
                { "ka", "020a3f991b0229e58080bff56b65d4ca968e69db8d318240c251ca70c032ac57ae07f54cee5c685586c71d2a79d5f764b5871ab9ea766f9606059103c1a9f844" },
                { "kab", "d19d5016563ad1be7399c563cacb59b2b2c489db9729ac27abf513dc2433adac7f395007f04495888ca88fb2fb6584b40ecf2a778faa004643568bec686ddb9e" },
                { "kk", "477ff3d4ecfeb358e0c3d1e24a56a219f9064c5082671e2d1388cab669c23ed8fb0915b1f125988a26dfefd43a8e74b1b6e9467df89326de82aaf37350da3514" },
                { "km", "f0ddc09205738a53048e37d8aae7788bdb1c979738f733df51dd24b2f2077fa6b4bd483d6976c553ebdb40240daf7ee10ceb2f0169603ddf00aedf4f67fbc2c5" },
                { "kn", "664b8046c682d1c2cb49a985c42084764d30ea9bee2e5c3385d762cf6d98baf8c15ee211ad790d97d193f1cedaa7cd3114f9ab3cc92688d7a6a5c8aedc88f6b5" },
                { "ko", "3897e87ca78bf6f5e04e530c55d06483aeb9c022f9f37644a5d55e49bd8eb960093ffa7735cd2dcd41b39a8fc6bd58eee2b901c0d55670bf19a0b8578b0b1665" },
                { "lij", "e4c9bcdf1211af88f9f73d2b0d5d56ea872b55a17c6b1e5d1864ce04f05a4b11427a49a70a6f7d6d339cccd6f02ef7c2a86abc9782713facfc2487dd8e5d363f" },
                { "lt", "bcb3db891c3566dd68452d9ba16edc312c22407f36c0d5018db168e7f1b111c9accb9326054433e42e73bd7cf28d66d93d0856d56c2d0cfe5dc0594d1297d475" },
                { "lv", "cc7a7b0a9acffd2a68dbe7989e403fa70b6d9915c683184eb3d1ddb93ace18ef48b0bfc12f41caa38403e905c84de2ecfbfc6e34417f84dad433e96d3bf082c6" },
                { "mk", "ac57eb7af463aea5101fef8ec3fe3a5642f35dab1348790a34fe9937c2692723416e861b603b48bbfc9f0054feebd885759ab7ce7b754f002f3e4f8605905b59" },
                { "mr", "271c87c9100db8d46db933fa2b899a6a898eeb1de757598f9c33c3e8c4613a94432bafc8f76568b10e2f5b596c8880e3e590cae937d3635cbf0147d075460acc" },
                { "ms", "4bed0fce95239468006fc1f475e7d537dd8af5c2f195d460414d84eb056c6df357adef81feb543a95f612b443b73fb1dfab4aa4f7848b436553c263c47348e14" },
                { "my", "ccb208306529a4f49744b0c93e1b5e68fbc9cecad2ce1ba6f11037f4e5c36dd7cde7ffa7c16ae4cadab1179f7f7ea8264af5a830e1db2279aea4a354a992b071" },
                { "nb-NO", "99ab604d5702083891e4362bf54efdaf6c59cb96dc0e6900fbefdc2b898848d8fc0e11abccfa33ae065f68c9a2365c13469010daf179ece8b8991837c8d5cfc8" },
                { "ne-NP", "e1112cf7a44cbecfb9f73ad14658f98f8d5175dd63392bd56c4d3226f793237705bba3f619834b0f399541664dccfe3e3bc48f7133faedeb509bce7f8f66abe0" },
                { "nl", "f013adb6a3fc42994fa873a72d920022c8bc2b4794e2732ceb817e1c1b21d9c84c4ccf041d32edcc4d833dabc8e30a515b7d7533dcf76f28a252518cbf08b621" },
                { "nn-NO", "ebb0309ad4f173d95de6d6003a7a26ba72cdadc2f82bea25139f6db6a25ac731083b9dd9d0a7fc4e8524f221aa85cabac031b52173a10f40b162aa4abe83972a" },
                { "oc", "462663e2f795cf374ce9980442aaa8ec788678dac36a319271b92ec353105b738791a8ad0d15e7ce72d92f4956c9487999ffc885016ec8bc33286ecc50ef2d9b" },
                { "pa-IN", "50c8fe6ed15239f8372d70eecffffcae7cd24d98a731afea7122f3dbec6c628d515543f04a3de2a626813331e0a2521855b8cfd7c86389e10c254a9baac27e2c" },
                { "pl", "45984509cba70277451799f2a8ee3069fa22e004ccf4f11d93e466ac5ee13d045f958da43d32e834a7cb1576b91d371a934a29d91803d61a7b5bd7e3e299da57" },
                { "pt-BR", "01323960199eac6860c859b0ccfc8f2e36c9a6deb3807e8db89c9a89e305f71e6e3e66f307843b73488ea7162a0da6bf448a1aff8bacd64f3bb2962e2998fef9" },
                { "pt-PT", "f21f1de115dcfc89c6bacdd785e20187be650a8f47fc513279dd35066a841d6aa503bcc8e93b05b8b25270b0d2b8ac6194d9a255b96305ee3cf246886d36d81c" },
                { "rm", "50a8cb6d3f1661d461f619384d3770821b33630182848cb05fd5c9fa956b000bcfd416508a39aa06e59b8cd53813860badf1fa351560a49666da5f39d4b9d62f" },
                { "ro", "ba4de3a645e1b5b5cbc8aa519f455ea58fe91b077b25b8aea98ac1ec86c32bc3e9641f7178597ed5cdc8cff1bc3863013627d1772768afbe1d0bba144c811827" },
                { "ru", "bc3d93da04194c23f0285e4a29def305ba137bf9bb925ed8bc2f7c87d6ceadac5a55949b3443bba47d8acdc6407d1a72c2023ea049717d011bb7f358e4ae7e27" },
                { "sat", "ece1752b537ca715f3cabee86da2a80522d050017930f5f0f6db454571588f2c835ae09ae2a74085f05ef7d92cc8e44b514e670ffade15293c203d22c2c06f43" },
                { "sc", "e5917cd417d8d27140db98bec490d5f550d6edb98a86cf9ab2f5140e5ed03e92c4e0eb84715e5c275391843816708abbb8fb5729ca7139d8cf1277cfd43e2b32" },
                { "sco", "1446c67ae45cd03e20415a3346fa0cf1d4bdc892de0cfa7c0e559b8ca710dadc3adb33db464becdd3aaa5e7f79a7118f409d9bb123baaa0016b308940efc57d1" },
                { "si", "c5fbffd9bd1d110f9b732d30fd3911ff010db795f22bf09ba0e6d9af0564e4206f1b368a1726d72d342a5737e8ce18fb0f73e971ed8dea87e513bb8d2460d164" },
                { "sk", "f4bc08d902aa26d40132ac7a64db11f580348e76095bac8980e8fe3a66046d03ba35c3baa7671c72011887bcb133704b96033e4262a3c7396fe90fdc7d9fedc3" },
                { "skr", "aa19004d00801a623acfce242f35eaba1f97af51a11f747b40f11667ede666a323ecc99867139a06db8d335e5af3e7f54792616d86375e021c3bc5f824d84b4e" },
                { "sl", "ef56cb469cda159f74792d49ea2b7b1189749b8c7b7d43509345208b84a631109bc15ac2bf877aa3d3448bdbef6cb75574fbbbd86cc1d7fc0fd2156efbebea63" },
                { "son", "8b0ba058f1d2a650164a3b6d54575eb1c8f3ff7c27df7ea314807d11f2131d3ef85d46dcc6dd8ea6534e796c6087a794e9755faf85065a246652f27417b9a843" },
                { "sq", "cc13ffcb8702120709509e40233921ee382c3c77fd3166805225a11b0f227825fafae21c5b7b6ebfad70b31f31d664a449f76b5c128da98196475178cc14b058" },
                { "sr", "c8f550d665b141e1cc80ea5fbab058909e3271871f563b587454ceab297a7a58da65802343a918354c47deeba5b95e7e197e4f94062dd1deffcb556ae5f7e202" },
                { "sv-SE", "5defd14d6d06bdcdbba48685ee45ea5e0abbf3587d0c8d3e6a95e53f4474ca54c956a41fdd2656148ff4869f323b92b37d1b2275e868b4784054acc4b85e3271" },
                { "szl", "172d6afcf9011bd7d0c88a46a9bb430aa27921674e0e3d29405482107c62fd433bae21b3fb630fe6fecef008463360d887a9985ad833c22bd98b0cfbfc8efa7f" },
                { "ta", "9d36fe9578d640b342f85c2929ca41a7ed18d6b3ab63466213b342725760f432e0bd919474a23ffc389badb1440129f0bfe08ae0155c47202f8a1020446e2362" },
                { "te", "d7fd62af089a0e5d3433be1a4f89b7ab882cae9b7d984d173ea387274af949944c528b30e7ba2d28777c0a317d74e34da38a6c657f534cbe5f1fc140d984189f" },
                { "tg", "5a5638e4b979aee9c69e34b4e8d17a875fe1bcc2f38d06f153379f529c0fb3cc2e2022619149bdf0b46106b058f2315e3db854f386d344da3b755a6db51736b8" },
                { "th", "1fe22fce9b4c5f640e834b80789067411768def6ae3e186ded44ad0442ade1e61cee83c12835e9fc98d2759d3834e40e428ac9a74e78e7731bd7110220f176b1" },
                { "tl", "d214d741996cc4a0576cbdd3a91f403c7fee0741261f9e16e98e66a079f1e130fc76ebf8da5c31903146262eedc5324299dd88bceeb83010d11a7c3369d2d7b7" },
                { "tr", "77d5d8f25caa248a28843d289aedd5244d9187316efe3ade360e043ca03a61003834063b56658339639ac9b1df1987b07f5a9f382af72d50f558056db4df346f" },
                { "trs", "7c4863815851dd044318e98e3a5442b46c7540b8a0284907e814d280e1b25d8928f38f5da95f7793b2c9540a1b1fdb6ec9a0a50d06b69da65fb49078c08c8a26" },
                { "uk", "c883642cbe2e19cdc6d14de9203b13aaa5fd0085f8e4a24ad95be205181cb9c8129b21d67995359dd852296c700862f6843eafc71f33b785a570b83c74c54b2c" },
                { "ur", "eedcddda61e6c541064f183241c638ff47f690a4cc408abe81dde4afadd6d7aa7d4e6e62b9028b5f8ad7864430b278eabecc2da9049fb445acc994167b25fc27" },
                { "uz", "9f5542557bafb45525739e20472a4ef74d16df9346f158cb0fdf9c94f12a5ccfe2235a6fd8ef266a16b8ac1d37ed538f589a7876ac923e0cb79208839154a47d" },
                { "vi", "dd844bc187bc8260162bcf41883dca1df1ffc83208b054ae17478e82b4eea41c2186cd8f386bb1547dc24483128f73dab0bf2a48722642c6dc7e05c92e234a5a" },
                { "xh", "bc7343c0a59ee4925d065a84f27315717be7404f7def2c3cc9e0a0467a8e1bf3a109ab780f2b820c5e9d53681c550201f60d080c54b89c7526b84ca502ac0a51" },
                { "zh-CN", "495ef3756d79aef9cfc5a6e98ffc1a0b4a720bf923e74b772ca73ab0656ee9ffbe2f08810816f0fa775ce69637d443a6eb68585d87fccae9d3b5ebba41390b41" },
                { "zh-TW", "1f2f2f7f62d44abccac6f80893a12a488acf209dbfb56513609c123d573406eaf8de2b4ed377f9400ccdfa2007703e6d151c755fffce84c9143c3fa7ae856544" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/139.0b9/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "575a5f2511f76512fb85251fd9824b86090f64b30ceff3509557a239459798247c4103d40b94eb0b3902e271bd46f8b44315f426986c19bd60dcc2cbcc9e1373" },
                { "af", "e08737a1e340aa1565da6342a9e5241c2d52fb77d4b3a878988fbbcbfd20e797d0a0e2e6a653ae32bed4946bd6e1f60fcb2d3cf425d08140addfea3de68af8cf" },
                { "an", "7ca2b80a423ed80c7a3ade7e15704ddf5610f7eeb0d3dfeb899f2df3c95574e944ce80abb4a4bd0088d4a3e221a02c2e4876b8d61a6a4f2e0fd80038a2b33011" },
                { "ar", "1de169586b7b7c57570b274cd211a4dca4d7749124b9db010f48551338680b7a0db91ae122ae38f620b46021d08cf578cee65f8e7441766f14fd9a5a5c5ecc3b" },
                { "ast", "2b76aee3a33a1d121f96ec71406b7b9361bd41aa40ff76ce8527acdc0d3becc878279c6c76ecaf8a8f3e700f078a20088990b09661602dfa22e9e4a882787b92" },
                { "az", "3b5486d904a45dd2b965287875257cacbb380b80c524eef49b7d991521ea59137a3b07e2742ce1b0693b92b732fd15ec7dc3d808c9a4d5c534e3131586f2ca47" },
                { "be", "56aedcef34d84f5ad25aac9b3a2fe8176738f0722c561d5d97986ffa0134fbd0df1689bd632d4518f9cb62ab23e03c09309a147ef6cc2131400e518bb17bbad8" },
                { "bg", "dd9e5af9868935e4a26a395eaa3a3d20c5de9ea01fb473cf1b645c92a6e1c1f873fccecace78cc3c17f2cc55b7631784534090dd2673ca46940240d69320e572" },
                { "bn", "d8788086775f488c2bf7bf31eb5b6212838e0f4eb592218b6a6ab35f402ef69432cc9ee0a9f3a5e0d63f877553c42a9cac0f4d70241d55cc1ace6d93008bb46c" },
                { "br", "5f46ee97e1c0e8718394fe42944edf8da7ed435723f84de3c53ed632917fddc91df16bfeb9553ac506a2bc73c2ac2e67671448df24b805dabdadd11a6599ea56" },
                { "bs", "c4a2e8d3b73aa4555ba6a30663901eb35606c329b6ba9afdaa076aa0f79b18a33afbac5bebe8f6176bdfdc618972486cf75eae0f89af8995c5ae54fe1d46b044" },
                { "ca", "a14b09fc506aa5017e4f0b4cc8cc8ef1051aa9287fcbfac174b6fec7ac52375d61c51cad5e1abd6fdfeaba48790787be71adab2a24aba214f8cdb0d781092822" },
                { "cak", "c042817d9493e7cbe8bcaeee59935a3e3a55fc2338ddd37c0b671e61af89e63b8e5692ee859f4a0b6c00db734e6f5ca704c5e8ac0bf68807da8c65a1d8919708" },
                { "cs", "fffef63e8d04794edeb49553230dbc4103ca4eb446522bad9a989ad7f2cb5c0edc728e5837cc5ae9ab6174287b5b8e0e36ee8139f6237b5e124b4b9cedbb9758" },
                { "cy", "d5628ea4f78a21b7abfb96a3ca13a9ae8d29f11306ad023b1951b6be73723fe040ee86b3377fd8497b3112bc04e00603ba5bfc4a8d049ffec80c67eb4fa60536" },
                { "da", "9deb54c66b466c3740902b81fbfcff208c834568b6eac3f7f0d7c3a0b8ddf5ace18d908d668bbd0eccb4b922633fc37181eee7b27d24c8afea3c0eaf95abce4c" },
                { "de", "57bad8a67d933ee1ec8320dd2ee410836f9cdf3bf90fae423f65458aaa7a09c18d14399d6edbac040b5d7e35e01fa38038cb5b9e1133fda4a199882194c6064e" },
                { "dsb", "978453698eafdb054f5c45ad575fdcb0954d4fa49ca95e326099772aa9821f9ef4341bfc3aabcca7426427218bd5648c3cf8c90bbf8e5afa4e3958dcde3dc647" },
                { "el", "1bcbbca2b4b42dcdad19d031437806278640648a9582d83e9a00459cc8320f5b654f804cf4157d2f86dd8dcc81a357a60115f67443ad6675a18f843807b58edb" },
                { "en-CA", "e31ef6ad4a2d4b854bb49c0ed85d76eec130bc648f4b01e815740f9c86ed1de46cabaeb97eea6c1c5e79b1545d6ab4db2ebf321aab57a52939fb8cf4750e417b" },
                { "en-GB", "6b05c358374f030fc53384cd06fb45abcdce0a30b0b359e39f2ea2c77379e4c1cadecfe40bed278e71652e08d9aa3de5c5e5f272719b0311a932f72a5e70413b" },
                { "en-US", "75e79d16d00aa23eb9963727880e492ba28c3d670b73c2686daf56bb9ce9dbf756a7639f62ba1710f246739401ff6736423872601613c451cb31808c132bc376" },
                { "eo", "0b1c54eea63fe12d731969eaa9409245a85fc2a50f6375eae9f3f8428cd110200dca0daf809f59738d6ae0758b10e0ae9548854ab17c455ebb4dcdb65175e450" },
                { "es-AR", "9b6d392d149f6b7b02fca4d79afea06dd6727b7997c1bc31579dbc0a789ba4db54ee9b32268e8baa92a0d4a2aa7fac8b80558371d0bece0972c60b25bb9530c8" },
                { "es-CL", "37df0ece670fc311c3162901a8e4506875802b102f4a219803cf2c5a50397ec3fefc9d45389651a8d29cdf0c9dfca215d464df751e4cccdf0e9f80d0d6aa7905" },
                { "es-ES", "a2c1ebf0467b0427973fadedaff140feed93b73e2ffd6b6a553536d3cbe7ab457121f5980b00ae0bc2d9a4d2f3d1c61f664fa1b3134e8daf1845d4e20baaae62" },
                { "es-MX", "70f48da7c08d71d3023b2db40595e5b7bfae04681682bfd334e0378d370c5f14c394884394ef9eaf4f59502488c08dccbff94da7b8f6931b1ee86cb7de5e3455" },
                { "et", "93208f7d81880b5b1b95ca4b5878b453a8eb5d84784af6be3d9292c887da946f18b006926da2ceb7b9bbb5042725b126b8007ab79dc24ba5e71bc865c430b65d" },
                { "eu", "751b87643b9be4cdee254a4872e82e69011e04d473d2104da6e91065a8807f22c21f8c6f3133027f8022b991a5b9bafc20b1f61d46b64caf2026ec7b0995fc59" },
                { "fa", "55248a51add1c5393c1abbf70dafe8079d29855c86e5967bcd42d1c7a01d8dd524f904a106201390f7c6b312f3317fc831fd4258d11bcacf190e0449dcd0957d" },
                { "ff", "a93506ca14c3bb6f4bf2fbb0735364ea3c54d2f371e7d2e53c794bf45148d7d78c1e9ccfea808ff6501ee35610488517ae4ccabdd9b7925bd81deffe9410f1b9" },
                { "fi", "2b17a2c534f914cf48aa6ba58cd50701b9ea98dcee162c1e35581baadff0023d6bfe2e06718d8a0d607a422a9218774b0538a4b50160feadc61d28af00d60f55" },
                { "fr", "9bb9c4d006b1fadee877cce1284fd15b304ca3b0b39f18456841d3e7be4a5d6730795850039901eaf9662b94de9394c3f917569efd07e7daafe23ca709cb8b81" },
                { "fur", "6c6174c7319a647326c4fd51f8c117cd681df34d6b72199a2e1645a1d50a5f51bd9ed564e36ef9dd070674eb2a51db80a24f460a66855ef98d2f8882df190c55" },
                { "fy-NL", "5e6b9391f0b582b60e6a574fd41799a957539bbd7ff5d108941185d5d442ba6479d805df1751e6f694d6d0c8643ec65e7c0cc619749856131dad71dc7c7a8282" },
                { "ga-IE", "e7343036dc5c68ffef58c0ccfc13ee8696e4d8131b045b2427440b48e498d8497919fc3d8f747a77b3330ee0cd9512f179b687ece449de3f536a5eeb295b6036" },
                { "gd", "ec7b4363c00022f0715e14281fcb7ae3eef06226eb6a1c9463eceffc1341ae79a2e6633cfe05c9a92f01f40d114366d202f2b1314ee4a7e411cb503f14dfeeaa" },
                { "gl", "03547ca1245701dc367dee9ba76cfc51e62e63d1bf0bc275735f1930eb08a0cf385b8081eecb47112bf6cfe831660a985ae264cc174a667dffab3d5b0bb80a27" },
                { "gn", "954b828574ea10934bf2b957853cfb8f615e5e89fbf78d8a287e9075d584488742f5ea1be0465603be9f7bad2afbb72807f5318a0a6b34df5340da191603a823" },
                { "gu-IN", "786eef45f74a1eb8b321f0f40722fae4dda33db9fe55404d8ded8400097fd1898472830c1ccc70d0dd71837de3ea1249b4743f0c530cf752bb8c0a22602914a3" },
                { "he", "aef6c903cdb375c4abc56df0774810c5e9cff2c1213b62a0daad8402e3bfe8c2c5b22672d565143754224d39d0984ecc0c13ced5d2ddff15948c35ce415cee4f" },
                { "hi-IN", "cf5b1fb630cd829b531a08a6d48e6c45d874113649d6b68bddbbc049d55f261d8a14d682413756672b1a5ad5be6c376c49decfbe2644de0b40d01ddf7739fb3e" },
                { "hr", "497ce4fb502bc61ac61bcd1320d27f8b867c5b651b17b67e1f4746aa6320f153f0f88716351d02a2a938c583d530d0293e60ef36708b71c79d69a333347c4b12" },
                { "hsb", "56f20d3423d0e5525ffd03c75239d7bc4ce038670f767760f9502f094a88629c989f2bbb4505152fe245446ad09f6c248a25c443dc13fc4d1ae279aa6f07a986" },
                { "hu", "6f1519c11a05f0a16dcc74739a2527a649e0d6fcdcad105e3457aaff5983d161af22804346c885d7fdcd18dfb6a1fbee60068023ddc8ec0fc920f2f648cd4ec0" },
                { "hy-AM", "40678075681583659c0b21fe4bd57a1fd3499914a96b8c5588d535be8b4e494f779ac67141175984433fe5efb1b03e74d60cdd4dae5a3175ae9abaa77fe5f933" },
                { "ia", "0979c982ab696bc8bb0d9d92dff62184ffcb844c2c93fbbae232ad1da39d25bcb6c9e38ab53ff8ed04785959679c8b327faacd6658ac12bb7a78ba677daa583c" },
                { "id", "278c5b5bf1c21d3ddb5dcdaddb95569285bc639470ef96bf24e980a86142f0a43f169cea231bd9624f735c1aa5d2bbfb3d62e1f948983e382d22c2a14da0b6cc" },
                { "is", "9235331b537c1412304021415b2c49d5a56578bf42c7018a2b2826ec50c3f911773769dd370036d0d6e5ecd962fb22e85cc23ef8088b7dbf4014d3be000b8daa" },
                { "it", "113a357865cc62ecb8ff2ba16eac49ff63cc072e37393cd8357b26e4d8fbf9a34e8adbb3f83c6f99624379e46afec1aabddb63fc02876f74eaba359dbe573201" },
                { "ja", "b2bebc3e22151f77d53c99b99f7e0cf23dbbf45e5a26df2cd7db1dfaa7eae2d67d311e6c72c1759459d01a2dd73ee1ba9dc8cb6e7c68f149fd76bc204ac54194" },
                { "ka", "3f1a58c9866a6c3094cbfa1e31ed1c0878d50bade738daf75253fb49f1e5618f593ae70ad914cae13543edc4e894ee42bf4f823b95c0b54e9fde656219e9ce0d" },
                { "kab", "800ee4cb32290aa6d63577861ff1a5b8c2fa2df05cfbbdea7054dd0dafddcda647a7354bfddfe1e60e9bfd3724972b95f70fe750d8ea55092248214dbe3dc3b8" },
                { "kk", "cf611f18c9fe9c72fa7ec7cdf17e907e8fd7d9e33e0aac20eb652f961c95c42b09a6ce064cd432745cdeff9df7ebb08d8d50321cd4f70b45c41e6145e45e20f7" },
                { "km", "3b931f467c402fac5038f8d563e20d3aa94ba398eb66d7bad119020525fb1ed13c8b53771ca55a6767760397fbbf324c0245fb2f9dd1638646dd7b246d98fa37" },
                { "kn", "48899c045fb0a07b5a9a074593ee9bb788447fd1911fa46dc6c4c8cf446f8ddaec97820a5d5e48a11cd433a4f216d4dc6a2474db34ccd030ea3beed7bd8a7721" },
                { "ko", "0d22a67d143ee0324eb3c622a1ffc766c09223bc23fa953488133f781bdb984600c9ac3034cd80bcc0e02d6635c22195043a8707cc931fea003820f9a5054be5" },
                { "lij", "14784ef33b95219823e3e74aacf7d890177fedad6d27562a3637045dbc73f9002a8af09d48d6929eb6c931c703427bb245298b829a254ffef12271afeae1e577" },
                { "lt", "3f132b0979b7618e507baf824f4c2bf64309d0105c663086b59aab1e7c92bef6e559cbfbd1d69d2cbc2c157e48b5f18eac73bb392b70944d239dc5a530911c8b" },
                { "lv", "ea5277020f566e825976be189ab242575853b275b163de72f2856704059907406ef70fce9d36dc35cc238607045b49845a51111a0aaf80d20b2240c34b876db4" },
                { "mk", "79dc3e477205fb9daeb7dfc0680d2e1982457aa48e66ad6b8eda72ee7e6efcd632e69fd1e60f7ab0cffea18da6857c41e39e49f46cbe8dc42986e55f8fc7cedc" },
                { "mr", "16058d3ac1c653e4ab80ae7fa71ae061710a107b4c48008990c452eda8f9661898d0be141c3679242f82ee3f6500ab0c3a54f381f06a5323eae5c1185973e874" },
                { "ms", "b251c8aeabd0e1ec9aae0025b0248a08281860754d67b7d252f16aa7f53940e3b3ddf24d976041e2d8e8e59ef9361a81b960b52ade382cd498577fa71cd4f031" },
                { "my", "fa49bd6a2ebf8379ef6b5048e8ef90988c1518ca35388c88906fe8710fbdbfab510c8b9ae22b7cfc5d5cf3dcf195854a848fe694cd47d2775563f1797f76fb88" },
                { "nb-NO", "40c26c5fce8cf6a721e82cc1b0f582def159e689512a9a90c636ea2af378b1b15340c2fd6df437a958825769ef640529e287c43846bcf3a81f4d0705a6696a85" },
                { "ne-NP", "a2b98a920dd341a7cb749c5e1683a15fef565a1fe304e854b4f6f806facdc792ea4336f4eb9127b064970640bb559d9e751136d5a41cb333ac528072529aadb4" },
                { "nl", "925c7230d2c01d6f244e5c14759d2827f148f093f127e2d91d2cedd04a14a4ea4f77a5f014ed4576451204128131d4327bab174780e418d81d4ff8dddb03f0f0" },
                { "nn-NO", "87e4476a4b4c6126f4749270257ad7ce6aede1bac1e9a34444966c3b15b534b22f4e99fdc5d1870e056f5d8a045db8a90c83df0a21a916099d79e594aff9fc44" },
                { "oc", "5048936ed6cb1aa0e6054eaa12ce1949e919570b04aa503c577420461e9145eeb0d8dde41be7948191e6540d9c56da78bdf0ea838fd3f1f4bebf0461896237d1" },
                { "pa-IN", "232d5a6bf0aa0d458376279d28520490fe1a90c6676a5924f906fda980604fc91dfa52c98c2b4159db5d6163f96ea6796600305c569360bcb56979d8f8936e7c" },
                { "pl", "fb0db8d7830f60705a7f44004bf75837e541c1e305ae8ef9464123e7f3de6cd334a27bfe69c766daeec89d317b6e989601981d6e92281077f7c61f15f419946a" },
                { "pt-BR", "860e631dad7ccf763d0a8342a84a0087899c9f506d9fa220e8762579fe059c0339406cac61bc04fe8ccfb4872d8c4e3329b5c4ea44af646b83bc6db609de8f2a" },
                { "pt-PT", "8deb4b13b6daa294426e4cea28ba948dfdf561d9bd80c6d164c800020ddee2e00de326aefdd43e7c887b966541ccdbcd8b6b6084b19dda482f61d5397576e58a" },
                { "rm", "9a4589966e2b66975c5df08aee19baf53ee2e60cd4c093a7214922c22af9b35709f2712a9beb659e33933ae089788d3cd8967de92d6e02ec1d9034758bf6769e" },
                { "ro", "10a13b2b3dbae06cd5617a7e6f7acb57badc1aaf1d1f001f9c40d09d7cc9a16cc705081a6c83c2e31524a18ae31cff0566a7cb41c29512d9b561ddb47785329d" },
                { "ru", "29d0ef34002155791364c0f5371e24da3c11196ed802bf0251a5413fb3392df98c925bd42bd5b34af7895e1b66cccfea7eeff1766c37486a11777c6da4882add" },
                { "sat", "3d8ea322798e2a7f7bf772fe96acf2de6fe3141485dd550534790df94d85d26b08d3f37b07b12412ae3d53f0793e058b840235c578ce56f9ca6344aab917d6e3" },
                { "sc", "b479d9ad3db9edde644550838faf97009177626f86bad46d6cb239f86ee5ba68361848863f37a7abcab6b6cea29331a37eaefe907ec76d526dc5e7f5446da67e" },
                { "sco", "82871e576445fbf956967b906589ee776cc0672d1dbe1956b36f4219b0f7e3f5e3a5321352eac1b45f6ee47b03ad95aae1c41619b3e96e8699d731ecaa715afd" },
                { "si", "b97f168d241bdceea03b2bf21de36fd7f4023b0fb20bbcb4ab798b6a257f7e783bb8b5184fb0a578b574d15562dabc0cb3682862312f2eb3899e3f997fd697ec" },
                { "sk", "c547bf27f26b550ab78c2febaec95273c3239874c08bc0ee52be87a213e9b79dfb8be34ad5dd54c20bb08c33b9f1a5fa907989a87ca774b5fdbe56b2115d12a6" },
                { "skr", "bb3d468295466c27f447745194c8bd87e6fcedcec11419085ad1269aa22e470d84874c96e699fdf11008f554f52789fa23cba5ab8aa6596e0a9a67f8453406bd" },
                { "sl", "5e9a56438ecb7580c4a55239f211e743e4e4ec9719a1cbf03587d568bc13412bf9eec3e164d0785680a116a2642e65bb455882bbfae4133a4267b96c84700aa7" },
                { "son", "6ba774dd36a49c41faa0f2e2c4cb038452a452d360b2f0b96cd2cdacd1f5082358c01912a0104a6c83a9c1b0907d19ec700317087ba1d9a81d34f591563fa60a" },
                { "sq", "b0dcd5a5ccc70e5871f1aa24aa841321b3b89d4ea37d132d1549e994215730e468787c51f9377fa1e6bba625f35b74912bf74b5439e60feb677f8c50ec296c1c" },
                { "sr", "3b61405ff297ce24acb8eff6c97076388fc70aba4825253dc0f83dcbb7bfed295b086c1bd5b96c6449ccee233fc590c047c7874987cbc44cad36c163f510ebd0" },
                { "sv-SE", "21ffa02866689679d8274877b274b5941f88c16878ad837caaf4d24fbb3912549e420921e2754c2ef07fbba1e324e99a3d0dd007f8a9fbdf2af908645d8198a1" },
                { "szl", "ea7cc6ead3290b4673a72400a25e0ae74d3b820041e994292d620e9e53b109897064052235f9296ef4e817fb0198f29ee11aa59b29935ab2fd02d00c095354ab" },
                { "ta", "cf9ea9dc68a2df3ed445c0fbd886c74076f8aa773124fbcd4b2242f52099a0c7b94e2ec84f30806c1e25a17bed88b313a7dd1395dbf77a59b2ad2cf7a94d91f1" },
                { "te", "9ab33bdd2c43da24d08096d6f396fdfad5aae8459a253b844358e5b65b20322eb4e600da561c8bde63e6be16b2f5bc0bbfb5e18fce577582c3125f2787c2df27" },
                { "tg", "d88efbc406bb07902ea10e7bcd7f3c757316110380da983faf2260ce1c285eecfab7498abf069540725e1775255085317e38969da7d633314532673487f84534" },
                { "th", "f9d51594f14415d4fa40655a8e041f700c703ef11cb4447c93850517103039cb6bfffce0c7db98eb04af11aefb6d9b04c08f75d523b785d5fb13c7dac310d1c4" },
                { "tl", "94c123dfb63ab4b205f0870cf6a4fd1fa689fbc6f725a88923115fd5485bc87e0cfb5ff1c512c9cfea48a57a9f790179c3602b949c29032c768ad06972908eb7" },
                { "tr", "4b94fd2c439e3cff0b2ae6411e198ba9b670119a7b9c049ae84bcda9f9d3ff142ff79c989211420ce993ea5146fe3d6a46cede259a8b3d2c45160bf7cda1b609" },
                { "trs", "4509a12a05899196bccebf9f5c4f102d4ede4ac1d64a7ba6c1d5e694f3ba74fd9fb3e52823ac379acfc9608d196a095ffb838a1afcd4a9832ec7be95f1ada412" },
                { "uk", "8948b34d582cc665786335258550968ef67761af531c3ee5f0dcf87ccaa5caef3183bf43ab7a10b6f15b03b890c9210a50ff35d73f410ae89b444aac35d170ec" },
                { "ur", "58febc4cdd8fea34c2fec194cd2d19320ef9b5971ad39ca09579fbbd4dcfdea4d3fda0b2b8711d6fdcfabe76d2056cb1a9246db96242ec6845dfbf2f30eebe3c" },
                { "uz", "89bd717073e9d25a27ec04ae095fea15764116fa8ac5bffacbb7d92f4a1abfd46021cf10858998e7442c50178ebb30ec2659c774b3151019b6fda2e7ce6e913a" },
                { "vi", "2cdabc793ae40e7c9ebaa36f07b099a93d657ff07a71441045ef103c9c2142d8d0f9fcc4db2ce3d6264f1df01c5f1930d3e31b62ddd8f26774cd10a578ffaf17" },
                { "xh", "c87aeed9571dbdd9d63661baa100094d2610b547b00adcf727dfa34b473cefcdacb5c2bedcaf4f020359448d5e4af20a907048ef775445270de3c112aef46587" },
                { "zh-CN", "378b6b8d54d8dddd17a837bc1be1c8481060b6f81ac6b804f6838b387805d205582e61017f13d7559a782f2590130f1816607f0c271a90e5c17719478f327e58" },
                { "zh-TW", "6b9c683e3167475459a3a619199703c4a7ed330feb4b60647ae835c59d70a2f9c98b78d961e3fba322f39b91ae9f663f68fc6939df1bf89cf2393f25ec802347" }
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
