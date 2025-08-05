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
        private const string currentVersion = "142.0b7";


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
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7a7622f1f3b8d925c31f44606c45dac25a8f966f42c9c5e7627e841625de52fa9fa1bd7dd41ff44c984c1bb7e1818e1e76d910250e6861d963f15b56020289d5" },
                { "af", "e53597a02c6b893322395babeda09bd04dd67a44e6b0e88fc101cc82c905520fedcb42d048f8e27fbd28a56f04bcfe22083e4b4c261e8e91cb157f638fa43ec1" },
                { "an", "21e5751709d0b17be96c6addd080d63d19f6232dad121bf7aa67ec93dc186951b9d434eb1e650ac004f7ff55e8cdddc0e1ce84274911d067f650b6e09022efb1" },
                { "ar", "fb78bed7c839dbb7c5b06c1969e92271727e0fefe35b697de108e604e99f9116585c27b16b287d3554a0f6ffa236bc541fb58b9b2c744c136db5f84c8a1205a2" },
                { "ast", "7e28631b8cd57a3eca025842fdc293991e3358c0e5fa4f33e073177d8a1d09bf7f178f670ed757981f74b85a96f9bced9120e6bd384014495110f37d5e1a121a" },
                { "az", "703e539d8c0564a6ece50bd54ec033f8a3d9b4d8173cd669b076727c7227fe0cca0642c6c27ace33f31f1f4527444b97ee75875a673599667728d74edfbb570e" },
                { "be", "09d5edd379301c4b9fdd19c47af8a824443e87c22afe81c13b0ff7edf4bfc7de0424ac90ebd9532beabcaffeeb6971e661490785ada6968625f5ed062f0e9323" },
                { "bg", "73f1261d10567ca424403799a96cc8d29f01d6c44c241e7d4bfaf0ae0fe2de5c1d928f1cba414b5742291f482def2e105832b9228c9fd37a2d15f8c56e6482b8" },
                { "bn", "367cdf0a971686afea741fa060156a33624ff8efb5b0bbd0de3aebe54cb6774caef1440edf27c09f7cf3bb4f5c567c1ac3866e480c5f0092183672d5db2ea0a5" },
                { "br", "ba72f0decc9def615434cfbdabce50c470db27038cf28ae25473ec9ca26dc6971595838dc580bf3ba5adca1873b004e6633a458b06ee4a94800d730015b137cb" },
                { "bs", "69b6d6800b648ccafda5bdd6e01d968e009a21fe65fc0d5255df6162e3f53e4cf69ea8a8e53d59021c2893f7588a3dd0d95cbd707fb960ece50ce5853a0bbb48" },
                { "ca", "7552173938a9fd12d180b37a67095f2f2c854801f264c1bf1cc8ca6a0e5adfeca74397e36ecb02649de1246a615afd0a903b33b1518a49997df911191bb092e4" },
                { "cak", "e27d51cc3a3df0ebf26dccde263d4a31391a9dd21bb767d3384afaa63886957d170befd3af7942af587ba3ca268be8382640ef23760d2c022ac8f864b0291758" },
                { "cs", "6828be0c8006e7ca441790ef9ef96d88bd53432dfc6772e2facc765a3ce9849dde3cc380f4893ff0dd23d3c67993ad1c7d73628b1f8a9347eaa52f2e053dc678" },
                { "cy", "35781026e7240f6ae8f8164397c3b89525029e04b689f71bd23b0221d5e0b17ad120328b964b3c4b7b2d830826e00ce558dc9d3f31fc6929831bf87ba4fd8ba8" },
                { "da", "bec9a3914cd57031e4f8ef57e7a7bfe7be644956b2fc94f22204702a49c17aca107773e3adb280a5d54afdecccbf9a67870c2c0724479c25dcd0306061dc0dbc" },
                { "de", "1a0c4c161f803db3ba95f52124776c123600083524502d7b2d113e1114a91056e2213c1e2e865ab4b4ebd9dd001a7cd652d3b340857fc86fe66e7ac74d2388f3" },
                { "dsb", "9aabc7c53ac63830388d6c5b6f59df8a4f527bf5fcfdd1545d2fa9282add757da624732600cde5fb84d4085cc441cd13b1e9e92a528c46970160ffd2a3b32ed1" },
                { "el", "685a147bfbf9e0ca231cbe9ab9134f842637a979aef0ceafbb4020cccc3154b54b40d2efc4dbb2f7fd0c9c6ce7e19f8cdf4e64e6030a34aad5feed1f8eb0f349" },
                { "en-CA", "171da18ded77458389a31ec3c921aed5a185a6ec6755704c60e3b74c605dce9f9a8d034c6e29899722a900fe5117452c69c60c7ed604dbd375dccb770ff7077d" },
                { "en-GB", "815afeb4601d1afe656e6c112148479eb4cac14ba6719b128df3ea96a6f11766262897240cef5b8a4cc775395e9e793b8dcc8e705772630c5497743f44206d8b" },
                { "en-US", "a5cb18260fb748879c0d860973159ef51a520111a105d006966beaf70b283903a120093c2b1e4fe34159dee46ea53f9c7c2a52da98395b74e9cb49e488974213" },
                { "eo", "49585f7134d7627dcd121d13cf4517ea869e5c5b2fb42b36615330cd04e9a8817a2c7be97ae4472295095e57cfea956fbebbbead395d052160899368126cc626" },
                { "es-AR", "191daf072ba87a4a3d9d3fa86a8d996f7bf90a666d536e20bbae49c3b0f3f7577f5aef41e2559e029b937a6f586a0fd9fd138465df69c321d4ab71aeeea274de" },
                { "es-CL", "987661e3a4c60de057b55915199093751d89caacf4ec99827c3ef0f16ac15ba2033bc4a2ac212254f3986b6d57ba809c400b0dbbcc4e57c7f3213de49535071e" },
                { "es-ES", "6bc5273aea3d45ad93c791992a727e1ad626197e464dea143593e21f86c8bf538352964aa2253c479f1a9fd4db545277016d24796da9eb03cfa8ef79f99a06ab" },
                { "es-MX", "025cd9e278a659d722dc115038a3406d63f798287db369beac82e684a4565a97bce951adb495cd53a5c9fb241de5b273a433d007770b586623b4771bbdc7bc55" },
                { "et", "a797b54f5153f1944d10839653484fe985b1bf13531b06e98d571c2768b0f1a7e13eabdd27e9c5de82a8945cdc346e53c514f48251065c21d7b746ff2bbcbd64" },
                { "eu", "bf0fed0436016e7c99e8be02f431cd19c8afed8e945864c47e159d6119576015bd16d2ad97d0c933e054b7dbabf51d79a9e9b6801dbab5976613669864d096ff" },
                { "fa", "fa7d29e8401a47761b5a10a657ff3b04f1a0734daa72096ee0dfea33f15f08477b58e657ceb1a5c4fc74198bb54e416c04ac3844323d34a635fa652b03dc6ae9" },
                { "ff", "1b6d829fc3c0aab238e224b9f362f41323ec566fc62462792be0af5b92a88431cf45d4eb37982c720b135b1b68c990b824e3ae9d283c0e90cf17e722b8a4e757" },
                { "fi", "deb0bd5e4cac22c405ebcc745da1bcbb23f2c3992485d8151c8693f1f1faf55b9135ed1703003c06a4f18b92c7160b26826217078a75cda17269086e3610d38b" },
                { "fr", "7b409a6587f86cd34692418c48267acc74320a2b5b66452b878be7758843911dce4b7a714040e2a3be13bfc3eda53d8e4a92534dc22fa2ef98a48d75960d0e79" },
                { "fur", "c76cd5109fea8fde1123b74ddb9e806214808826ae7785f21843ec5ab577dafce88f92d60c57fd843b04d7b09a89b847fb9caf19bb951e6a8f6b1a147679bc7d" },
                { "fy-NL", "3d6792ff18afe4207a553489ac9d239500c099ca7ca3f53406f96488bc05bc6a42c34f8b46344d55385490d0cf9c5f49c0e69f2077f348c8b1c1436c4334d532" },
                { "ga-IE", "f15a91c65cfcae7d2bb03e70c0258970d7db672f88c01f5affa560837240ff924cce416e7c37ea23ec6a771935a8c48818f08bbc7a84c5512c5fe5034e1372dd" },
                { "gd", "f9a5746f7d7cf5af24883c748051ba01743b7c14987d2d05dd00a18da69e7da8157c57f002e5381e03e4d89a7c7b530fb7e4168da001f01bec8f21db89aa3b1a" },
                { "gl", "586632474db5aaa785a39143eac415aac5d11b75a8fe643752efa89b75c50f7f71d7e6a696da91cbdcf94cec3a31848f8ef07daba8bdf31c721c2fcd6113ac6f" },
                { "gn", "527a2199548c8bd9e5190512a697536fdffb759465214b3bb77358c460ec14e7a0492910725392cb6a01636838dfc5c3e369ae0d70d796ed682f8ce20eb77814" },
                { "gu-IN", "8abb0a72624a6924d3f1aaf1fc90bf11b1293fb8cac1720d0d855ea073fd8b4266281e47782710c8f6e50960ca9c32409fb1cf19325edaad1fd4347c7519f88e" },
                { "he", "6ed4cf687938de51927d28792c15993088049ae83d66eb27d09de40ce0a65b37c87256b0eb67bf9c5367a1fc85d1e8d1ca4f33af4fa5c129c7109e7996d34ba5" },
                { "hi-IN", "13aee5e96c8a274a0dd596f59e2d67cfdc53a97b6e9ac31f02b9aa282c97753ebe59a5b8563818da4dfb1e861404d6d356e7399e424da51830ecad6f0fe937c0" },
                { "hr", "fe3e424c3b6a26ba91af1f963a5052b1e58f08c837c5e9bae3614d8b3fdc7d16ab5010a5d1f5560bc5ac1df1adf13be5fa9737e0a2f7968f7f80f9a937ea1754" },
                { "hsb", "ad88a6fd6125d0b3e61f82b8c262d191361fbcb2f68d9ad976eb36114d8b53ee00d8dc26d1a564ae74408c35d4865a45b335ac8c9389e1fe711e0aebcf83eb9e" },
                { "hu", "fae182d7edd78e75bf1be165a3ab829b3abbb6beefaa4eed17305790c328df139c3c9f3b7aa7db5266668e62a1abeca4000278ecab35ef2562c1f611c309cb3f" },
                { "hy-AM", "8b25f162b77db44379a3a8b84aa97ecd818a5840f9205c99724a0d06cf27b634c476fa4041e2af6525756d911cd20d273e7c6739c0d4204bb5707eea71018d3d" },
                { "ia", "917ee4495d9fe8f73ee220d683753dffbb143ce4282c45c00c90e8e0886998d6d001e08d1691bf6055b92745184324612a049e34fdc72685db8dcbc386b5f32f" },
                { "id", "f2ee5e19bf95c63f84a7401f6c75915402c12dd293df288d2c8e2efe210930bf073a959cc6d721171d67bfee63db8d1ad5f30bf98dad58f7a0e1ab7806b7e266" },
                { "is", "3d78246cb2ee3e242637d2a345e728fc4371633cc1e2424449eb13ad63fedd2035060ead5b338763f7055d12e2a1eeaaaddae931479af667156ba4e48ad6aad9" },
                { "it", "afd5670e77baa0713665472308106e3f533907c54a7f460a404a44aaab154d6cdd7e2047e8ef49c2ebc32bf74bbe238d6fd07519ce65e38956a59c7a37250f76" },
                { "ja", "8643bc459c9fedec97b1a5fd80a09c07b290ea9c822856703e296c92ce0e397750b4b2a86c4a41b706f5e6b4bdc19caaff28a97fa02d362fe4105cad36a0a2f7" },
                { "ka", "62202ffdff58b468664bf566f4892224a22f967eb3780909868efc507c9c233addfb18ca0031b62cfd6917918db7480ae7bf7fbdc919d6917052f54428967cbc" },
                { "kab", "f3330356178e487bf2b3b4a433f20d64d906a7684eaaaa703e612efc51d10072dd2da395b987193281897377144de38fd1fe5fe64aabb4e40aba4d507d0bd8dd" },
                { "kk", "b6897cf9109c5e72222c55cd9412cb56dd342f067c6b4c33eaf63c117501209fbdf64a441af920f94c355cf02cbf12df4618abfede1477558c10b90f5a24233b" },
                { "km", "63902c415bc83f4264959fd83105965bfc730ca84458d82e7e793c6928440834d4378323ed0d286c18fd8b805df62d7aabc426694b9f598c82f201cf4f345344" },
                { "kn", "548f635fad072855b11370ab59757f77726ff74193b9c329e5fa41368f19c0885f4f27cb97f84915f053134053047efef4754d0cc74a0a5174e827993cb85e29" },
                { "ko", "b81b451560f19e0076cd1debd721a3cf9e245a302ec5fb9a1b9aa6595c1f97c276ed661a8f79ccb6569422f1267f6452285d2412d41260fc1c838efec19d0063" },
                { "lij", "4820e34dcc862a6631e85b4613e33a9fa92adf24c3c49464056dca273add4885364a8f382e9295141c1c41b4d6de390e1a993499e135b014b92e4030213161d3" },
                { "lt", "a7055f482224e50baf7efe09bcc2aeaf32ffe3dd59ea82cf1eff4018e4ee8879ab21d1f627c55a6a996b23ba8678879419a48843a6d65a2d5c1ed10481e07eb8" },
                { "lv", "f534d73fe523555582c3e57bc87b36f6699c6f8789398b55bce2e834187c206f909a02e9d7e5d16a0e889c0a3c8c79693ef5425d22f141746e084673fab865b5" },
                { "mk", "9ce0fc0edad9f504a2550e3df208153b68a9b2485cc107ee2a97b46ad9eb22d4773a44c51ba2e6c5556bd4f6a55b2b9ed1ef9be8b012fb501317b925e1285b1c" },
                { "mr", "58f607ef42eb95bf77ecff0e3fe3356b4990bd76f10b70aa743b6caf0360f0efdcafba3a0951a65d4f4658015840c7ce54dca974b597bb0b3fe34bceb99f7376" },
                { "ms", "17df8f0be9f9fea885dbd5b3bc0b815780490b13bff8851bd9454fcc0ece3203029355159f069bc8f7a1c37ad22a2d23224f8250da57652c57ee0eb3cda26b01" },
                { "my", "8037fa7241eb127f3b748912c2854e2c2a18d51fead63acb4b0bfae2cb3a72af1c7a05ad852ed439cc0f8e6ae307f731c83aeac635a5b087ad2534a4faa5cdda" },
                { "nb-NO", "2a324fd75130c9a0a347d4f06badb81ea47a792e88f12aa00fe9da181a023725526b4a5c578bdd6985464579cc3d60fe4b7e3841b8df50e8da58017fb752c171" },
                { "ne-NP", "ce4f322e1abb4954e39ad0ade8de173cd5d4caee886f9cbf2f5754fd6af50bb2d6c81c607e368ce421d07a00aa9edac380980e7c263747c1f3f076543c0478c4" },
                { "nl", "bd48b9d512c57c3a58e59836552fc9d32c2aa37758bbc57356911213c975e0d3bbfa4e3c6f1cda83d7e631c94cf90edb1465e926633bbe18b4b2abed7599e873" },
                { "nn-NO", "aaf5992eb9aef6d75845fc263d6e7a84b703535d181e8ba42703cc32d5e3bb6d2fa8f0a656f958fa328d9b1628556625c544f35f4b6f3c75fe70e6bc86426aaa" },
                { "oc", "9808bad7ca54958926e17b21ab4fe7cd8e270fe142eb7e6a2434304882f0f311901af97a61cbbfc2d7dd19902f4c4811d4ffcbc9339a9cc1c33c0cb9db691e5b" },
                { "pa-IN", "0a582d459e7e9e8bfb9c1570fef5a8a594a068236598434a8aa7b551d93a864e506bf0b6afca6e96b874a8030ccb9124426a8b2b6797abc845825c1a1a430126" },
                { "pl", "772d2f5c6e3c4b3c57a294bfea814fc8d464981d164046b758d8e819cdd766e2d9f9781107499f93f9fc7651be05a04d9d35756062015af51e239ac6ddd7aa99" },
                { "pt-BR", "56790350bce44840d0f31e7b17aca37df69a369f967034059d65c665f706c7ab00c46b3850d42e486f6d5ed22e863f28b49f19ad90e66d9c0a6a5116c33ffb3e" },
                { "pt-PT", "3e3d8ade7aded9cb13a3435a63e08ad0d9c54d4e5ce2ac58f36f243c89cb972d7a4f0c3c5b7191cbbed11b5416eb1140b5cdff52da721271decdc7acf9ba151b" },
                { "rm", "be83387f14ee1cae4d0816696af17ddf877cc81c683e9065eb1ac2ededb9f66f51e3b49ffdfc4d7355aca64a3e32a729de96426ce69a0ac3a47db767b5e4ddcc" },
                { "ro", "38b1c943ded528c003ca7e282f47cfc23be16a776a7132f782bed0802e0552d19f21b35edfad1c530eda0d13121107a1e8c889c52e3747a5bc1ef11f07d38907" },
                { "ru", "86d10e4fcd9afae5e30629be04131846df787c7ede3f6cfb70c34ccccf1d8962dbb1aa4ca297d8c71c31c462362c10a5bc1ff67791eaaa5eeef14434350ea8c4" },
                { "sat", "4fc858b234ad92793cf39cf4f77be77828785faf4e231f20670ed7a1aab4a649ca7c3c80c824b21c3cde860edb51c6e836bdc7a81d817be59a611dd86351f3af" },
                { "sc", "85675b9e4df94f080da71ffc02844b070335c1e64ab0d2a84f07086a6f092c95ce9e057b9bb6f8a46c0063159bdae940c5210ee27ba0ce1d5e9667a89d703224" },
                { "sco", "80d5779f45bfe53e389a0c40930b81bbfce7b8ea48df9b5e13461ecf342114f6ffc6fcb0679194980283326577542c4e102bacb2182014a7801f870a906f4a0d" },
                { "si", "a6c1f813a21db300a2f06d127d4cd847544f77c1a2f12a359a538d6ac66a0367555ccb73d5d7b2c8ec6a284941b15f35ccd5a7d3f16ecf0bedbe0325b6c8900e" },
                { "sk", "e5868174b2da31f5bb547cd15576fda34e95d43e7a2ee23bfaa298fa2991676a82f1404f182f41af6cbf416d12ef045946a9d75d63ef20b533025c5a3439d65c" },
                { "skr", "4d4599066646179e64295ab7a46b107b66ec1eeee0277e95fc7e2880f5dc49985e8d81a026ea9aa8c84f8972e7ef32c503a1725e6ac225fe966120a3b1f6e7de" },
                { "sl", "a0d2e7d31900c05bc8f00b91abad23382685b66e8591f7ea30f7414155be8533d7fed0873b21b9e053205d02c27dd0037440820637fdc3caa3461750a7b939ca" },
                { "son", "89736e738baf718dab7c18d4003c7cd11ffa517e6398661903798e6860c013b51c2aae5b9c7d8cb795d05f6f8c2bb35c4cdd0bc543ec08cadf4cf70d12d6a3ca" },
                { "sq", "4eadcb96166b2b37b136013e8f520541ffc0cf366da4fed0495a081e2f1ca574481097dca7e9736b7a8ffd2bd8cf5860590252cd44a8966de540d6a98cb49ee6" },
                { "sr", "02fc933aec4dd981deac506471247538aced2a86049fdfae0ddf39480b917ddb276108619b2827c555583c4d4b5bc707ce0d4d0a099d636b3d658a6fcdbc6590" },
                { "sv-SE", "4c0667e71b97a944ebedaaf9b5e213a25ac10e3e058940c8c00a249ff35de68cde4510fa04352a6b3150f9faefe33c52c066430124580abf9eee35f869ad01de" },
                { "szl", "1a2e0e480f8d5859094a51a3e5ddd2f6e5a62d16722ff02bf5fe1bffadfa548b549e6f581f40ed8753f91fcefaee0249951d058baed528d64d41f168feefe0fd" },
                { "ta", "166ebbc9a9173d2eed7004e9e58d453a5ac01bda2691b6eb7902d6f7b4de1c09e1e3ab52e9792a5e57a95a2b1c210277e7147d286f638667fc31cfd0d72d2de4" },
                { "te", "ddab431311357095ea32c2416c7f98b63fd246b411cd3d52cf88c5149f48f681b959af21ca83409566d9bf94751063f85c0dabe60a51494b0f372c9d91c104a4" },
                { "tg", "4107fbe2f5c8a34c81e396ead6f2b4245c9f3c4dfd3a678096ca95b2ea03f11996f405a3ccbe319f7ded6dab6c6e862e6cfb8a031af17f621758c5b06f7ee924" },
                { "th", "30ed0d51fe303f95671ba7418dbef3895098af4d2181273bddc16cf26f15084b28916d7dc25757573776d50140e5def4bdac27f8f19e4f2fec195c9b9b11359a" },
                { "tl", "0b8b847fd2e895722601e8576277a99012a9efe70cd162c9becd6484ead7a6f76c2ed9dce47d19437306a1863406d2cebfe1a1b9df52bf26b80cf09b40a8f751" },
                { "tr", "bf98696e58f96acef81ae034c4468e701031a688fbf939fa01aafd0a060f19c8f0d1b42328c709c9bd79878633c6b62828117f7b28f660e47d4e5415cf716d2f" },
                { "trs", "08e9f71d19f21351395fc97af376aa0ecb3e4008d0a11204c4d34af8ede3828eb4180157c06b6acaae407c283dd1c6dd9202e7f07edf73393b2a8e991274fdd8" },
                { "uk", "2ab6b52041bad5b809ec1c3fe9abb076deca3856a06dd9e8dd7edc7134a3e0046594464b8c3840b772431d3ad66f438ba638e25ce6a1b1d739ac40b3d4f21280" },
                { "ur", "f6c3578f6ce91d77cfd5594983d8dbc06736ecaff2808be1228925bc3c4c60de15783f96b9aabd1c755b9875b9711cb1207a7b24a05ae6f3fa3f2b000ca91a36" },
                { "uz", "80a7c36c6f9831f2e1617d78d4050c2750c2e0f328170d7fcc483fd29fb074300a2bfb13ce277ad45d5dfd390b667f75895a3f7f4a1a974b592810382581c851" },
                { "vi", "a256ea29c99af01ecbbdb250aa053b92a97d85fd9974a4fe518fdb6683977c63f93b02db0555510cb9ad5727e7d37d62488e8775e3b7a1c0020ac28bfbe2df0d" },
                { "xh", "9c7b1ec117175a1ecf0df7ee0cd546e71073d434e3dfb2fc90df52c445cedcffb98c28dd6c54ce27b4c566cc3c5d05e6ab2b1627a3f05a0b06730655b644da95" },
                { "zh-CN", "d339305fee29a51bdd4fe23bf4ab91f584939940496d3bf2f411c3301074a7734e23462d9137a884da611b01684e878a4b8be0dd068e120224d4559d316b9b42" },
                { "zh-TW", "92c8511ffa7e15edae393865b1aa4cb967285c194f5353f1dd5916e323533142a21d289b955c59f0e69cbb6251bf6e3465ba70d959a416d1828f57b67fb5b140" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/devedition/releases/142.0b7/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "8f367f98ba255395c4f75ac3fbbf265b255b1d8057e64ac2066351ebd336ee872f878581f816256ab70d11d838e512fce8c2754798afee1062972055fa92b121" },
                { "af", "abddbf668a0053f5c31667cbaa84213762cbcd1a02446d85db0f4011952e7e3c2f28eb4371b68602198d43db25f98d1745e2a39ba749c6ed3078954b9a403c29" },
                { "an", "6f15446407d60b5168c45f4cff6c02d22345253485e52f63ce84efea7d0ef023c634c205ff79ca198a958c63e40073e9d293d96fda49f7bf98b3028c431ed514" },
                { "ar", "bb29694a59eca6f014ad75cd6b6e126d31151bcc684581afa35704aa53a0463f26eb03d98c22cdd403b2ee48b36edf037319a049d34034fa548fdf60d50bc01f" },
                { "ast", "f863823fba18789bf5d7fa39069a6892005fe9cb36c0b247c4dabc64e1ea2598e91970781bf5e5b36301bd7b3a596a9e06d8c6fe8450467ae04eb0fdfaddf92d" },
                { "az", "ab6d9f82785b316ed456cac7a761fa23ac2153d727b0a55970c97f2bc779b6a9ee4e8f44e9a66fa0ceea94feb411773f57d3833b6354698bf8e842c326ec0e12" },
                { "be", "7f42d99d11eb3d8fe5d7aea826735ea8a00fddfccd1dfc446faf4b062a30a49af915ca87ff7f7f6e2b826007bc824f36c8a213d885a40c6451198253530cefb1" },
                { "bg", "87775468340b84f74459ca8f93072e1de857c4aa6f7dbcf41d0d5d7288c65705e12bc13182d68d7482cd5e49015735ecf34c6108dde646f72e288161800cb482" },
                { "bn", "b4d2cf89ef65e5f6c1bac2fdd0c93f73a7c7a7b52864687d681149af9c7d68be25c38d679e7c2db7d987ecaec54b9f273611acfc17e3e3306d984492cb02c434" },
                { "br", "c59931a21121d357cd14cb55ed95c8a926e2962a169175708f26141299282c93174445a383e24d08213093b5858539aa7c26f772c53b830b7bd3b44bfe38dcab" },
                { "bs", "32e966629c4d88e54e20ae2a24c299d0a7cb8cee9ae5529a4d3b27bfa3cb50c540023b2e6d8910c69e7bbb09f56c4edb698263f1cb83a3c0ece34f87752f3d82" },
                { "ca", "78b485c8c7f29768d2fc90f607b2e6a51e66f619de278bcd48e76ab9b7bb268fcb156a311162740dcc5fba6208954bf1c1f95812b454af1425a42f20d40f95ea" },
                { "cak", "a549a1741e367d05345e49080dd209113c0e2e42d7fa4dfc38d3546739b9d6c34264edfdd3561ce9133170f83b1ce0d5c960d31cee5ae0d146b7bf23ba5d3f06" },
                { "cs", "542cbef4e8d659c1be96c363e10e32716ad81f3b6c57bb56348e2625bb8f853b6a956e3d718f8c626f5ab4631aa36da46529f3dae7568906a4b99b06b2933b6b" },
                { "cy", "934be47be3edc7fee8b83a4a83c2eea41c194ec6e6caf9be5bb048c95ce7e95fa9638abceded79fdb561407460ab0f2e22361b2bb305a6198de9277f62195be8" },
                { "da", "33545aa8cf69b6cb30727a06e809db5fb6caa14f07dd96341ebfac0762703623dc3592160d966f813c2414ce1e0f753edc13914a59e9e99e5bc17add7bde3f61" },
                { "de", "a478cbf14f81659f6feafdb973ed5c83e6ffdbef9c651be61bc1b62215467badbca099dbbf8cbf92d3068d6204dc77af8e3b069f2afe8f716cc2f4f21c3f9860" },
                { "dsb", "2efd6ae20c9cebd66df2a030a00f891cdf8c65911e97e6a16b59c80a69666960bcfcf2229ef0ea093be74c6234fe3e4a707727b1d03da4d6795aff4c5b661738" },
                { "el", "ffdca241bec6a9975a747f0a2705223cb152888abb9cc6bb428c5ac319e2144be9a976d3b8734236245ffb0a31542830bad968584840d563e76d9efd075458cf" },
                { "en-CA", "d1ed12cef9399b27a72f936be54ea7d66bef88028b435fc17ebd4679b2ea59366cd6efe8fa21e24dde96a0824a1a5e5450cb2ae868f46d9d9d86f5fe6435ab35" },
                { "en-GB", "52f58e62e33bf689066cb5fc3b494e25010e5634b26effc1a1e99b72006fd51f8a44fff2a3c6742bac0a986c62638774cd07948632c6ad8b55b79da6faaff751" },
                { "en-US", "f352abfafc363b6e5397c879089def83ace02c51ba8424df208813c95cbdd5f70de67589a8723e589f0eee5cc1910ddfc076c39fe8467a8333ac7a75694e7f5c" },
                { "eo", "0eed2b6f58ae9e71b4708675c4b648ab0ea6f0bef84d8f2913ec8700f93d492739c9519372166ecc9398353dab37aa413a476e90839120b0ad2786f0e492accd" },
                { "es-AR", "278d95012e463c281833fdb2f301c29b5f21015e37076d3525a15bec60df1e0bdcf36e68baedc024cf4cd25d234dc7d4b32bab3af5a7dd5eccd3ab398640493b" },
                { "es-CL", "04b19e6852aa981ad5a4698cff2a809eba98f1da5f62ad2bd78e8e6d3f495fbc217b4deb974a21ff9ba69075d4960dc491c7214f749b5ca36c39c3581fa220aa" },
                { "es-ES", "6275f9bd7887eb19605abdea84e71e7661233876c6e0f492323eb0e80409e212763bc39d6499a34da7fbb6914a25b01b4e91efe44d11cb09df394f3c6263c597" },
                { "es-MX", "a96e7b7f703b8efdd5bec83d1e30d10377d738e14bd04a1ebd28f3a95ecffd39e33be570c3fd37c3250045ae03542f7cefb86848d8f99a86e3a10cd39737808b" },
                { "et", "35fb4019d3da064e91917520f78c2058028107629b0622dc25f93336f9a45e6668b4dbd920aeb9743b63e78e20b6315bac0f1637bd69a741a838cbc538ad935c" },
                { "eu", "5bda4c443cdec2fc5f19544e4fc3b00f1401218b888888f1220404092d4484f70a35b7ec8b1eefaa5821d64d147572bb41de64529b0ead10dfc9ac7995a1c432" },
                { "fa", "cdc9cf52c2cb4c7756fa645bc7be0772cd198a00902bd87e1a6a6af7a86c071f56d9c6955eaf3bfc0522c60b064f37516bd8a7a39b149ef59cdbf82f687d088b" },
                { "ff", "9a995162492a4e85c32ca0ec3d697af838b30760379ee1f80cbab2e2b30d78b38201ec49cee80d84430ff820b212c5ca4d8b321e9327fabc287ce3232ad5a3c7" },
                { "fi", "633e320b86fbde8f08b1764e09f68ede1f4507473bfa53414f75380d31a958d45a0c84a9873d370fc34edb5167bc6db4c03685f7ff311750609d09c2063271a8" },
                { "fr", "5f9f6cd51187a06383ccf7011f0d529f1006281ce79b0d4c94b4f27a4fafe956380962b7094f2ca00e0641061acb63be5991be9b891e301e62cdd389b59ec8f8" },
                { "fur", "268680c483dc5e5345e8f5a3280eb0304f2de133f8a3827520910c39bb6ca4fe18b2402700f8ad93a0ec431e1d48e1208b0247b4be11d663da1af61621bfd3f3" },
                { "fy-NL", "0c0b1bb2c9cd3d257dc525c066c5bdc0bbe4fdcf68205055db8767a2ec20b2b227b9b931f2c6d90925d8c0ba44cf0b6ee2177a34e07541ad670a3f183232cef7" },
                { "ga-IE", "1b389a104257e05b7bb2fedda180d048ee1c10493f9d58f6db1c57e7d43a18fa6074a6f011ac33119745ba42e338e80d2d768c906250b106b098e7b1162d45ea" },
                { "gd", "c0bbe5dfb1b7b7afd15ef5e25df9fc03a8c2c3d37a3f698a631a44961c98207888f1eac9f541ce9d9513c2f3ffc915fe8e61536a29e60229939a83ba3eeae862" },
                { "gl", "48e8f3de73eb8dc09ed6103de366e19930937a27d18e0d5b520996e7e555c02ca8326da46fdbf85789ce4fca68210c49ffcc67317ee982e7dd92ef6524cbee0c" },
                { "gn", "bf821a79809698e96b39007d68db3620c05c0c50545f5e044a01d8581c61ff45a6672a2b4fbd428b34e1dc3fb13ba74e171b7e19c4886d3f2cb8cbbd45eea662" },
                { "gu-IN", "4d55739113f67c95aefca37f143940ef3b5733e127af65c7d8728bdbd02dae133776a7735d7efdb0a034a987ed007f0095aeff151e578a956309602db8d9c47f" },
                { "he", "964f23482cacb2a27053c468aaa074364858d1ddd9e841957b2c8b7657f0945416ff967f2228ea3b62f0dbae4561d465b85b3317958e575887e1b6ad98d3ebd9" },
                { "hi-IN", "fee3f6e8a308a699ba207be8437398aa2b637d81ba57851ea68e3d799e3a8d1c3212f5a1ca1a97d12143071ded892a189c0efb888a2cfd63c43f9f894d04e4c7" },
                { "hr", "7296b022f72a234d60707e6226a4e7225a757fcb7d7f27f48fcb5d3629349b9a92d442d0269a87ef5473269c48801e5cf9820a6e76812578b35faa11f93462d3" },
                { "hsb", "698cdfa07039541a071f797ea4e4a662278c50c45e8dc1689d3a28db88ddd72de20a998e488dbea48dfe730867a3015877d91ed7529d89708650beb179df6a0c" },
                { "hu", "233d495ce8733a03d474555e6af379c2067df41d033203acb4c2d4c3e8dd8839c29669b253b35e96c67cef91e718dc7b74974f0cbd8afcf66ae0b9004e2ed38b" },
                { "hy-AM", "08b30b20f15719818e8d414b3ccda98f5ea4e6e8b94e9894608ec4eca5b9f136826310c5dd87c50d43ba8e65e53502297cbdf9c3b55242c5d0170491a962d242" },
                { "ia", "162696ffae381daaa538d316eb9da97d0aca54b109bde447db9982ce2a231e669b94057b59ceb8265d27134aa52cd24cd9e461fbb2f0bba783d64aa09f54a135" },
                { "id", "d3c4f3a1d01a22366a9800055e06fec64d70c35915536e7ac215d57e93b6ebe1896f3aef334b6fa8f9b76e7614a32c8ff3e29424b62abc0ce5512a362d67b91c" },
                { "is", "1cdf4e70b44d9d02cfc86b0238478cfdffdd568859b0506c7323ea386d0d5d3f6882e314229af7ff105480c4afeb501d4bc907a2851b113a95007217ee09eb23" },
                { "it", "b64622c629f8c8ace2a19956c0908deab7b6cba33f9cb18d4fe37e6997de5a425adb00c9daaa41242ae7f130231d4c1e361e4d16c80a50a726885d207cd38c17" },
                { "ja", "f6c8ecdbfcc8b0094ee161168ceeb1b193c6483337fa1aad60c148dd5123cd05a9f1d17ec1dfd2c76f6b0f650e4a992e32d08c2053cb8ada53a727f56f83b089" },
                { "ka", "34cd5ebad14a7bcb53b426dc79263e338d1bbf924768a275869f379e0b1fb3cfd7c16099f4b28fc6646505da9c22587311ccdd867bfacf188dc88d117c3c4a3b" },
                { "kab", "255c3891e732954c86bf66753290abd3d1d24aa3e7c0dacbeb8ed560cef71214e817410bff52844b1832883a10015b5b5c526d42d4c6527f6a299113b939b7cb" },
                { "kk", "3b53b0456e070c36ef52bde731b073f765b9745b96401c0a5605af2b01b2f480d629d1f366f684f786fe60be33bc32ff2926de034714e0f9dcef7717d3dce2bf" },
                { "km", "2d9f38ffdb5f073dd4f50b0ab21e252aa42b6484de17d0251a6e31e9ff2a2e9e4319a92abe641ba2c6903b15fba4169db52cd6d114e3dd05ce02010318ff4d60" },
                { "kn", "7b820375a41bd41a58b733f254a3d4bdb78044446e17f115051225c3c57de1583f944dba8659f90dcf1e3fc15750fd84adf72319a3ca304721439b8448b125ef" },
                { "ko", "fbe371a3075680b390fd88bdf9c01cc255d573dd5d72164f50dd07b83aabacfe09eaf5fb80785f6207ebcf7467f171b7537346d863ec21ab998ef0985aeca97c" },
                { "lij", "f773d5b3aa158f702e76830a8ba64fac2f52907f8c54d09188bc3f4d594dabe14ee4f06278d3bffdcb407e3ec962b5e4ec89708b4b7293b9ff550f2cdef65291" },
                { "lt", "fd71910d82b18e5252dbfce00f33b94597dc1f59572b2c4c64529fdaa91d0dd9f379f1b313d2639293bcd3d3ea4716f6ab5873590d32ed43067073be622e654f" },
                { "lv", "5127badcb91bf672091d07ac247972b58a4e4f85edf241df8b87e6b1b49db2c2c2ae0d0bba97e028c952141e4488acada8400a3ff6858173673e3e04a2b0878b" },
                { "mk", "13d9c5fd9332fe1274a01d1be5d4504052e7f29e0fa1db0beb968c41ae3456b00738d8cc660de5920b3622d67c3a5c1eb1525753e382c56fd3a93627bfafba34" },
                { "mr", "77181c273edd370fdd0bce69f448be297715f2e492987e9fa953c70cdadfe8dd9e97459c2202a34b36c1aa78c0870435b6ebec24ce5f3ff3652e556dea22341e" },
                { "ms", "11de257edacf4363475b37783f761f6c1fb9c8b008bc1c24333c9268682621a150bf269740ef0ec02533fa7438796197bd262bb4cd582a942c9643e0c80fb72a" },
                { "my", "b927437479955d9e14350d319c2c120b2cdf581846679456adcd6e9a14f7124109fce9b5e4df5be7bd433dbc5ee33c351e943de1e7a16a31e8cfee127801afa4" },
                { "nb-NO", "edca265dce3bcd0fd687297645861f96d575b87b6d78f03ca45943c7e61042c02bf7e79d6b89225ba47d07604f5a8a628f3eb9c351fdcc071d8a72483d375b35" },
                { "ne-NP", "400f1e056a9e774a8c3e78b0d8d40f0f3fd785ff4e971887f097af7e4a076b8d088fc0a1b9eb31c0d0c9d94264592b2a7cabc15a9f04afbbd2a0ef1fcfeb08fd" },
                { "nl", "ed41b1cc81fa3b5b5afb5189c102057555c3b059f1ac6eebc52502c9e4399bf75add7e652592c45185b3574e66e6034688c9f170a46543b182b4550cf4f1cf91" },
                { "nn-NO", "69a4bf64660ec0828b379f10dcb85b44ee453db3c94fa530fb432d8ec08e64a6c435b61cbc46308a954058cd8e501414ae42d63fe87456082225d41ac5f7395b" },
                { "oc", "57de7ca1e917109560bce5e5c9f4a9735be446af88a208cda4bbd13974ca117b685ef8371aa9719618277c2bd8facae7db8fe63c4ed00d85ba4d55b2c20f2bfd" },
                { "pa-IN", "c6bab20b018a9decb4f94ae1fef721ee7f223648a60ddf51b48ae6f2b68d9d08dd2b020da0366914cc0ef6dff9e384d6d0750d7174fc5297d5ceb07f91f31827" },
                { "pl", "1b2ead87eca662231f2b2986237bb27feef78f5c5897a2573b32332a6e91dd60a0f259e0b96efb7e9b14a0b89121baab598d3ea87563fb8834a4cae08256b2d1" },
                { "pt-BR", "c5463ec08fd9405d53df301366e147aae863fd4574b2e20aa25c5985e34d20b85301dab1a2b5a0ad9c38cd784e2a74d5bfa39344cd74a1ee54618dd0bf8dfb84" },
                { "pt-PT", "bd37496dc3c71fdbb5c00e4ef3b3e0854677e066e3658c2416249d97b8d580507ede2590e44df1c35a2e64bed8d08091d95a3cde1be789c88ef019734490aa94" },
                { "rm", "57391ea75dd8ef3a6ddde935e0840b0dec2a944b88c7daa07d171d611a7215c275c435826287f7ce0d47b58ee08832ac48365da2f9c0f511dac34cea1121c8f1" },
                { "ro", "ef2e9b4b9797f845546a88e6a656d589ee163f8bc9b9263a8e3d02e25205358a56ca071f4f0aecf6c212de9f3faf06330cc7fd37aa8c02a31472b0aa32ebb40a" },
                { "ru", "d39a82797dcac16517ceae337831bff864c09ea47db3ce95fc5bd745cc6bc8f64e8b55821b1314db1641aa7e767ecdd6426675988e7a0d26af18a9b4488d79ee" },
                { "sat", "594e3d53b420ad06793b9ed9ed06f4f1bf18c07556c37b28b2c142fc9c7267f5835a82805444fbedcc80f23af45bbca415ecdca062f2a41b82c83852c4ce9368" },
                { "sc", "bae19d32bac3eedeceddeeac5acd22d11c9fca571fcf97da80c69f7b391235b6cf06cbc6381ee89ef371b9fc4ecbf7f5d32c97916245d6ced848a8430b29fab7" },
                { "sco", "4eb4bdaaf821823fe7832c65f2916235e4a07d781f01f94f7d2380040c8efcfc5a5ef2ad832a35c6edda8114a41a7be38abe40b181944dbd66b3d6e779cb2c6a" },
                { "si", "dd3b99b8ddc3598f6c12631e4b4d44a83a65d49ba335228d5f5a477e287f0e23d477f49b285e211c460d2d4b7e410e8189e7afd9a2830203b6b09eacded23900" },
                { "sk", "d048ef8c152efc7e1d219f8c69b517c09f4d1876c67b60304c821d53947c39c9f3b425f835971c4b3ca00679eeef3aa7eca4562b6a93f5c2b24b0e32b648ed61" },
                { "skr", "acc6118e4c7bccf0bbc1c7506d545d033e58c1b44bcd16b8f3c0ca1551bcd5c718be51032e78b247916534c3ed05004bbfe1aa01082417e55f7173193901e169" },
                { "sl", "b04c39f0fc84a3a97d3bb1582c77f7c47699de13f5ca7580eca8d89f6196096b9675d89b4ac8365d9dbafd01ae8f47606ffd6326b0622521d37193c1e31a2143" },
                { "son", "6a715f1e605cf3149b3de6c07a7a53b36a314c7d33ca5c29720bb2ea2404592f07c75a162ab256ca81257fcb6438b32d21129fd218befaa6bd3b9cab6832924e" },
                { "sq", "eccb5d81aa3c62c112c68be8513254f9c207520718a936c3a859e11d60521767a1e9fefbf5a41b57fb34b42a11d153884beb510aad9dcefff27106aedfdb7e13" },
                { "sr", "d1dd32a96d00d074c4326ae23dd20fa6199b47b4cd24ca6a10ab53a1ee0e0b3090b818d839964bdfc4c56d73955a993d9823729341188c855d1e3cb362d45d14" },
                { "sv-SE", "37504c5fa2d074dec60bb5baa0ce96c189d21b17bc4888a7d0738994864f9b074c133bf8b06d82eb81746ed4251529ac32788e62e3be44b3c43570eb3a6c7872" },
                { "szl", "cb6dbd7a5e1120b932d1be89072f0a6690c6e219fe8d38366566fba0cb78769aede13ad6e3977964b791a2ef93762d21245ab48e197bfa7d35a4ed5ecf99dfc3" },
                { "ta", "529e4e846d09802206aa86365adba63643a72725c8c1ec02bf050ecc1ceb4590f4dd04d2a827fd94469ab52dbf7c6f97cc2a556a47a41ffd95c193d1eec1c69a" },
                { "te", "ae79a6917643bc27f63ba80a55eddbb3305be14c8ddfa4814943c83411046f8f62d55c7afdc9bae06446d595e8f207b8c9bd5c429bb5f07799913d4d5912af0d" },
                { "tg", "36d36feff0caf872d7bf0fe87ec8ca6138c720d708f38f6006923e09ad1aaa4e863eea1d70198dad3032e44ca15be56f389570309561422c1241f98b9bbd3660" },
                { "th", "f33f0d97ff433b41fe2481b391d42a6506d73d065fbac8d02a1e3c5090401443614bf81795a9c220acaaf032d4088af8a4738624d76ed108f29ad9e2a4051477" },
                { "tl", "fad9bc8ce83e230e04c1bd19002e7bdfc0f03db051b9565dd69d94b3af45a0fa2d22843e088f5fca9e9e038a66499ee4ee19fc03059f0f8b459e05c0ea5ed46a" },
                { "tr", "d6be3b55cf9eb32b682929b9ee2d97368aea80b98770895d803b5f05fee62a6ab3b0d40dc5cb5b874fa4e9ddab0b90eba9b481947d0e259e45685c36b89a852f" },
                { "trs", "079d86fb5889e68dd1976aaca5539e0b92813ceba28f94155e7a5b67e91c851db3df25db3ba88de23c2f43eee2464b43fdc9d0d408f4435799cf8f2e206ff9f0" },
                { "uk", "dfc2b2c15b02b65f257651a437604a261f10d1b3e2ccacac6e2f132271e7841771a316de0317f8ac65f78730a1d094e43f50cea278d9884639882953c8850085" },
                { "ur", "4868e9258947e83d497b667b5d5fd04fa7e65a803f3e16a0287356c0fb5066e232dbd8f6615e1dc52a6fb947a9d29c2657a643c1a2a89ab5b717172698dd2ecf" },
                { "uz", "27c24d5ae3deb255cbd3f326f3c593b4cb18692c05c61ed2edbdd972eb3eaff8353d5080aac8f0fca10adc8986814a45cc0f46ef1348c1d8f7954a3d9c7184da" },
                { "vi", "85f9d901354de7a2e9e37ccc90c29424fc86353c97553891f71b5e33f76e6a2b55c012049debde41733ad969daca9bd3d36b2a4e3665fd8fd2fb23deb4ba64e3" },
                { "xh", "228b72cd68eb0d1ccbbf10df729a9ad741fb5cf4bafa72068d74cdbebc419b42ad1af867f3228f2cfe474ea85692f971f4e59e3a7ca8627cec6d8340608c7af9" },
                { "zh-CN", "aa5c4b1c631641b634191bab2392e225f3b871965bf80e516e01ededda38e66f5664063a5efea2dca8b2d1486984a5bc72479f1d520f908df909aa3d8ef04e01" },
                { "zh-TW", "c3b9ab3f9f9bbedc664969367922e17515dd5ac87999c7937a7d48e413024df13777c4cc64b85427c9cfd104743b223166a0a588c078532f9c7f95ec4d5b68f9" }
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
