﻿/*
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
        /// e.g. "de" for German, "en-GB" for British English, "fr" for French, etc.</param>
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
            // https://ftp.mozilla.org/pub/firefox/releases/138.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "99c95021f562351da8feb34e99ee1bec70b316846e18b4e1bbb12f7c395a9f594c35a9d2e4a6b4b8257dffafbdb8f316c796edb45e32ac24e7973a73ae6cd0bf" },
                { "af", "189b431bc38c6b90e9900d3349797b6a6b7cd7f70be123ceccb00077dd440b44ceeacc29da67d8331e0061628eb360e48b245238a419826e7f0746d7bc8af390" },
                { "an", "7fa44f92fa3a74cbbb51b9583a841159c0c165773501f9547436580cb2b5d365ca90797172c347f87ec36749668f12f315da5b6465160064692dc142b3285b55" },
                { "ar", "614ec7c34ad016239e642de105bd7acdf8a06d6713471c946acf0fef78bf2ca7cc18afe19728c19f6061f9721415cf07ea9c7f8f518fc88f3bb408bc43e9e310" },
                { "ast", "a88830afe2ea0ccc0d62a27c49b2ae0b40ca28f226232e5d1f47bd7699490803318fa7dedce76016139b2ece9277531a1cff34adcdae6061f315670582a7e7af" },
                { "az", "85324e396b73c40802b023e8feefe76e607c5569796f926a3b33a54c05d2f37c18c985be53acb2df73432b8761b699013aacfd0305c550008c109f84e20a5cf5" },
                { "be", "ee26fe98453af5340aa7f47af156eda319fcab74dd33328873c92c6d0989cc069a720ccf925d017d02d6dec01065f9ed20c860c97d070f3887704e083f54938e" },
                { "bg", "9225fe30620bb1c38ffea57bc9c2cb37914cf4c97bd437fce4c1f1ae6ae5f0edef29095cdd7e4110eb286c174ab835858fe6119a3627f657940d92b34b53a9c2" },
                { "bn", "e47caced0c325c47cee09965a1defbf076c8f40b22fa613ad7cb38986619b0f9a4a392a8f998e199c1c634683cf8caae0381f97ac211396a31d93d5dec8f19ce" },
                { "br", "395fc2e655ddced989ddb43eec32671413c54ba8ed4e0b0d5f4fe4039bd072f965a7a9631c3cc86727472fe2e439f9dd2b4c50f3fafa28550fd3349c463f88a6" },
                { "bs", "ad081602d207932cd496840c7591ac52cec831f79f4c34708a60a5ae54b6665b29a220de8d247adc4b40426d6c3cfb4694f47fa554a7b6c282a1499f7a50518c" },
                { "ca", "89539e4346c63b035b866802b1074250d5d55003f5826134c2d82b89510a196580059808b6710354e5f5ce2b550a708167a096e53cf31d60e8dde094e99fc528" },
                { "cak", "0f54890f6c6cf5cb9a1000796e1e093c7dab9cfab9c6cfac9f00b3315851b17733d989001682b5c34f48f7a52c234cc6ec5e1ea6e85848e0942d8e63ad8402fa" },
                { "cs", "617967e7b801dd51bd7ada6bf85a3ce7bed562ca87f407ec90a2774bbd5fdbff4c5e48cb3ee0f76e25c9b0a00fcf2208d567e2dceed2afe557986bc78da573b8" },
                { "cy", "ac92b2107a3ad8ae56eb47f9b635d6ee971ccfa531236a883012d9d65b5d9d8f91ff493f336b777daff8e80eda9b485188d752eb9e7302c27552bcb05e91af6e" },
                { "da", "d637e5f863295c00fa8c5aaa951e19e9f28711fb41c78aaf898fc9ef5c06640ae6b30a312be93d1ac22ae65602de20f29ec77bf7d8a877fb2bdb998a87f32cef" },
                { "de", "e2b082fadbdfd08c7e3aced3500b2ceb2bc4b8a7ce027db4f488890aa2f29f3bdf022200008c4d4c03bc74cff9a8916b4fd40de2afa56d31f1f95c5f65b7e0eb" },
                { "dsb", "7e175f4e89a950bfa7849d203738bda28247eb149d73177371decb8a74a00d3c516b9605eb20874fd58336c4d776b7df27170abfabe9c023e283a7a38487310d" },
                { "el", "9099c5709012032f0444e44176bd726664a81541f62ca078e7670fbc1fb269ebd2556f13221c6d0a4ec7c574e2524ff17cddb239902b5f21bb8e8b5832f4663d" },
                { "en-CA", "8f819a88c11f8f00bd78be8e37b33f87db0e765ce088b7b5bf0688cfd05d0112ff2c9fdc74087bb218a8b2e6c429da2f4ffa93e7d54991d68ebc41582f5ee1b7" },
                { "en-GB", "0a0f83a91c809b3fbfebb26d80248fb34ef0bc313485335b92ac0d3c862e4cc0132a71613d093a6af47325b3d93a3dedb284ac51f192abee25f6143a266053e8" },
                { "en-US", "85470a89f7cdb49711da6244d60c0aa37f334d016e6f78758ab6c2758aa21adce05be59089f828b353d98e4c10eee91ffc11b4dad486b7e4b21772b04d3171c8" },
                { "eo", "0a424ad883a4c74059566ec3c977148f06448a0b3f2ac35bdbda656782d4e5b7bbafb40872a652b4ee81071a6f92639065d8609cf972755d59cc015f281ecd20" },
                { "es-AR", "78cc4269e35d1516bbb7b0d9551b6f2115b7438c6d8538ba12022e3756a40c9a64487963c494a65cf45960ad90a72e192496bb486ece2f6c94ec3a699b3e665a" },
                { "es-CL", "c7804d2fb12e6f47da2363d146537c9bf5dc68d3f3a571d5cf12122cb1a530e36530e2d24b41fe9e2e8e8f962cffca2ffb1c512dd0d895d88180bfb7e8f8f8a6" },
                { "es-ES", "72312aa13039bbf0dcb939fdd8b05cdd011ce68fd42290a07484ddc4faf73b097d55cc988d855ba9742b0c72c7ea9b8bf771cfccf8e99009d3e643c4f0c259ea" },
                { "es-MX", "266d161d50d0687caf45b29a5af4de0b2a2c4257f5417db3a9db94a95dd605719d9f6b507cd93fb9707d7bfe87995ec9f9a587dd03a82856f8da4400c5a094d9" },
                { "et", "89162bd6eed20f8f284d1674f461f239c8e16c85abf080434c14037959180bbd3b30d7090bce3843488407e9280505b165ecad8e0af66b7c495b45f52c9d4307" },
                { "eu", "a3d13ab54c80ea33ef2b53e567d1b5bf3484ac1504cb171fe1f82aa3e287541d9700650af7a30ac5d5468ff99938d9f70303f839fe9a5aae5537b87157b9407f" },
                { "fa", "7eaf1be56dcbe8a5ffb2b598b82b68391b99e83b136386a7b67b0e18777d914be3714adebbefc2744e15a2bec87b88c83d6a0e375e28ce12db0835b83db54a2d" },
                { "ff", "71917d1e882a1f2fa8529c6317d63c97529354191f5b110fb679ff11d01fef30127db94effb5b79a87494ed90ff38d481a51e73130e8a56558778c2f1897af4b" },
                { "fi", "7e1a85659e308e4f45c7ba6b997536c6fce0cafeaf008d0d4df0c2649104a0629529d3a9aabff20878ff7d447621454770501995115d9f0f9a4155cc56b37554" },
                { "fr", "4fa2356ac42334c3de887e740c62e236f128296633ec9b6903bec1be27d821968698e27abb9b3b5739767a81a90546205ec20a8c9e1f192bec777103a06d2e83" },
                { "fur", "08df9e2c6b3064fec02dbf7d75a4a75f035bc71253fef005af52c98681a358b98b08f7c3a25de09b3cac66650313309805e7283f720de18be9783caf2e7cdbf3" },
                { "fy-NL", "05adfb9984ced3e6e9c734c16aca1b0c68e244aa4a56429ff768f49462e30675d6795c0209d547190da10e35c01fec110d9c1767244b09f2c8875a9a7d1ec81c" },
                { "ga-IE", "21866dc431e500cb49c4f592cb4e7fe2849f468c078dc0ff1f831f74e9992e1118a8292c74e9c9f2f1e582653b852811cd3ba4f79602d7e1e789606a8f545597" },
                { "gd", "1de67843be6f9540d1425d5babaee5ac51adb89f3e9f30707a00698b08e941f1842ef7bffa7b6aa17618ac5b6f59c66f8ac394001468b49f413a26bf8f7d920c" },
                { "gl", "0d89bec92d35590b4252470004184ef47fee8c9bf6fa47cbac0e5468dbe653ca82230764ef667ec54afec3a30bd6c9964d8108efa71a0a0c74e81c7cabf1efe8" },
                { "gn", "fa91a765256e36727b2cca6434122f0bb292afc807e8bb937db5bbb683573c7cc40b2bdbc72574461a2625f27a6a2f75f33a14d0bd256c8a4b972b838b645899" },
                { "gu-IN", "098e73ae12a47cccd8178462cadca8b9582df1ec4f5a2078851c2abbebedcf390f31681b5757ae61d8021e299615fe447389b234ea90300021ccb9d30c7e201a" },
                { "he", "8a8fa99e6db3b4a299db8418e7d10b3ab519b70ee6674a4a165b075faeb344e0af491654bbfb08f13b9f1279867c6b7478b4eaae8949e3416cb037182e956fa4" },
                { "hi-IN", "fffa5407c4058c2679630a62a1be44559ac58593766d1c7fbc81154cd6b29a5bebbc24fcfbb226e5f9b52d5cc47eddfd07e47a6711669a1239385be7977f3315" },
                { "hr", "e9ab36e2123c78c206b4e8837068b08a3bd9db77558a722515aee8410b5a7eb1ed4a6b55b61db9360a6cf21afc36cf1c2811993cda0a8457892faeea724d2772" },
                { "hsb", "5848ed5f4fbb69c37681f1a78c0c38e8d395768f76947c300bfece4b49b0e93b67179e21f0c505246935aff0db0c881ea9896f3ec7a5cb6c0c3d6f7aafa22147" },
                { "hu", "c478ad14c58bd29643f7d073737196403eefa724e9f89d1bc5501037cc03b174e88a713be00924ef2056d317cde1a45f3956cf2684c578be8a13148c2ff85258" },
                { "hy-AM", "9b63f2f8fcae6874441f6284cd1fcb38aa396dd624246df834e15548f3f785dedb5314d036a752b99c7646a340a3391814a624b91184f103315322a4431257e8" },
                { "ia", "1999663925baf9fa759b6200ab23ca38d13fa7cf07cc59cf8723b6cf475f7f6e68c15d7363815d0d077f40187dc1fe59f5a9d2a8a0e5ca45554e1d1d5d45d97a" },
                { "id", "fcce940c03aadf19fdc0a22654dc5312f8d3196647fa7c9f8de9f1d4b97c762fa5bd680c4866bc6efe98568f14d7046c598ec7ceee46a5291ed7c52b6e79b02b" },
                { "is", "b962464fe70bdd17084bec0f40a8fafb0e6c5dac7f8647a92b8ba7ecdd5e85703d69555d8b0f8229691c85115dc94850b36bed7eeb19d99d2fc5351cc0aa899e" },
                { "it", "4f2d52a2bb65ac889e21204c8e46891460bb7822aa89a597535dc7723c89c7c0ce7f4572fa4bc94e9114daacc335cd1c4127b7f33e7a207b30322b124945542d" },
                { "ja", "b76b37987cdc8bfb3c4458c47da4538d0314d1b029f405b35220577aacb9e97ed85c586901b594eab105ce552418ea501d1c3cc9f456792af19c20a1c783b31e" },
                { "ka", "48364206fdd0e4fc08bf9d2d8b220f158aa2fb771e98704aec82744bfa9f8add20eb87dcb3fff6dce4ef2f6360ce248a4c1dfdb58dbf24771b9374fc71dc1903" },
                { "kab", "5f01b6e724dd4278cce07480b549d83bcd18fcc6144186d43ab766adefd6f43815275f7e3f206be3fd618bb0c75e709f3960d44496977778f24190aa1ab14b60" },
                { "kk", "f86e3360a618e2d189c5b03e9a5bb0431f2203b41c9e991502eaff3e92584da5d6b9cac3eecd8a6796530ecec36f13b4c28ab3319ff506d004ec6f2ce07b6cf9" },
                { "km", "57048c77c9a3f7c247b1524a047001fbc14a8014c8d1ea15da897e289b6a20066cb57f3799a44dbb003cc7a466fbac9541d7c40658d1a377bca1994cc706fb9c" },
                { "kn", "9c603372f4280f9b7e538460959f4b4f5b5e1bc57c230af96861c7d5995858bf26e46fa16a6085c3343a70e8443d080c78366e799bc8d700a96781c2587ce5d4" },
                { "ko", "ad522d1918bcbe21f5a626b9a36a60aacad135e5bb0a53d51bbbae227a1657c0d5ac89e947bd8a7b9a9c42a0b2a35889939655c8eb3fa2b9afadb7dde1db5ca5" },
                { "lij", "3a8e6b9a1dac35b7c06ad77f0685b7a6279ad1d02cf9477ec5710d4e2e5a8601dc4b18410885b9c1338b60542109fe148f003affba8e45b05959b44cbc0cdbae" },
                { "lt", "6307c2d4373415ce1f45b22cbea333685fef3809332b3058c503d49ef61a3fa4bc4dfbe9ad65dabfa9112733f75118739db7970b40b82019d5bb648d660487bc" },
                { "lv", "ad9395414d7c73955e971f35ddfa29f1309a41e5fbee9eb79b905e66a86329ed76d3dbd64fd7b8d6669c16fe473bd1ea331de2e357b7a927ae4c1f400ad41eb3" },
                { "mk", "867962cb05f9d8815b00424d5c192a06dc0821fa9cfaad3d8ff84b33006ed7174a99ea025cd31c018caa0c53e3bffbd33fa47375ef4d3d61e342786617770d22" },
                { "mr", "c080f55f51ecc32c5364324432c7473634d79454b716f1293ddd59a538e7807a1a8416e45848e2529034bab3455eab4b1461015adfb01fc71006f182d9d1f0d8" },
                { "ms", "17859858d53075a1889041197be5fc71c9e2f2126e50ff7cce71724fad371635bcd90e5a217ebec95d7fdba1bc5dbb09fb2769facab19d27f46929d1acc0d33d" },
                { "my", "ee92bf1044b883daefa7174fd643357fd9d1eebf3981eb20bb45093b514454abe45b5b43ac840307ec15c79dae8033d88137c1996cb466d730413838e820e2a1" },
                { "nb-NO", "d951dc50c9d80507ffd2701ebdda197daa8dfe00019e71a7d148ae953fc699fe3245fe10baf5225ebb0fc4f9e24f9e72aba00c435903228adc3bd1be398a5715" },
                { "ne-NP", "13086e7b33b04e3a89cfc65afa3cf5d41d2a7babad15766a12252770030bf42ff5acb0716661ee979d64264d88d6a8eb627064fa86a9863edd89c0c012679034" },
                { "nl", "1f1af34254e9558f82787a655bef49ac2a25797c2213e1c9dc8ed7d37dfcfe0cd04820ff9fd0846c318b34ba2e433e67681537543077d55e948d921b4ad04b42" },
                { "nn-NO", "013294feaf91b3faa3a618c655d078c05776d14a49c5e5982961494aad07a4415d706833772f55fe89e1b51160bd64f0e5e6b0c9c96264c8db5d10ec1200a515" },
                { "oc", "6f188dcf6a6ef74c942051dc381f74899f363a099e6399be5fb52b68551057ccaa9ca831f7adca3e13282437e8e64611e387c731b65fde3d89c24b5fc7a795a6" },
                { "pa-IN", "c4f0fee7787f4426411770266346df66ee6dbf68e4f799e51f064e0afadc17f703bb6e2d46f8d856943b4e51d184865908d1f86a6518f91a2a0598173b2be8d0" },
                { "pl", "9b83a66671a9d9d748a2317806f79a45d0cab55894b101b46024e5dfe763d2cb0bfd781165e23c2103075bc17ffb844ee93649e935f14cfa26218123cc76c7a3" },
                { "pt-BR", "0beda3fb20bb0c33d72d8e4ad36f70a5ef7d33a46748265d8ec4075e093d7c516d4ffb0dd5b86072f4af8687924c35b814e42dde3ca10d53b28d9f8bc560e31d" },
                { "pt-PT", "bc53162ef776960801f1ba8d6e65d1c2e07239655330702ebaffa923f2ffd21dfc43237a12f13108155438f699462b62338c820cd8e35fc2df28baa091c28cc6" },
                { "rm", "c27ebc0a406f4caf7052a9d5b9c5351e2c899962c608d51525b44ccbb393d4f9e573b49e2475a7702a2dfa8c8cd064d0838695b778fc21dc4ff6dc2eb1e58126" },
                { "ro", "d06ec6cd7afab6a0d20dfb584c5d61ec4238ae15daabbee71d40058b5543d538c76bafd2fb9b4a5d6ec1205b2a063eccb41ae1d4df7c764a1922f6d2611a7eb0" },
                { "ru", "f7cf5098bd0164ca50f2269c3738fbc64e6ecf9391e71603089d3f712f37a66f6afd8bd61e08327f03234e81fcfa76b8a91ddb1e77c32245dceea00d0c747742" },
                { "sat", "d297d34ce0c871cbd9d7288cfa74034f9f2fcfcb6caafa15d2f79359c1f56a5bb998296ab4a07f0a98fca440a0b2038e4b836287b782bc19d5251d07c805665f" },
                { "sc", "a01d6dbdb4b7d16401df24aa8b4c79101ece39c02f194b770b8078c88f1bc7ad29cb2da3a766e7634a2f74061780f1109780b0777df2fae699aa5af9fb47ceda" },
                { "sco", "9427c8bc3eaebf7fe19e20631118e0877f2b93658b6a3c442fc40791353c984b75f9981eba8b96730d621ca3bc6f4847fa41d4578c383994ed15156ff9ffbc6e" },
                { "si", "a0a8abb5557c345684fe7133bb505ec15fb9ad51fd94c9dd8132d833a10b7768f3fb0a5e48c97a3f6e5eeb83844488eaa9987a932ddea933258d72f6afe09d63" },
                { "sk", "3bce38ecc2924fbba68b1b9195b2d4a24a658200b2c039e123dca763603d9d7a850d28d36615c327ef219e937962a0e1e35861a7ddf31fe8557e1a70941111ee" },
                { "skr", "7e28893b5840d33a8739391fbc1a08bd0e0a85fccee17ec65aa2104f761348ce20fd749368702c2bb17c730089b7e8817062e77d0a3e6678ba0dfa801a7cfa1f" },
                { "sl", "67d038ea0625f241189d5fbe6cf06f5e40bfeb90a03447564bbd4cfb6ce1c8014ebebb19ecc038375c6239a576fb508067f340107609e88643f9b9f8e6864bfa" },
                { "son", "a7ee333df13e83cfd3fc081a7ed58bd4fe691c40a8ca7849f142ff997dfbb6047e541f6ab5260fa1df44bb0da247f1cd684d5a6dc449fa804616bfe9f9161e76" },
                { "sq", "cbfd2031b341830bcbe7aba29a65a8f3249b8678ef23305a09ae16a04482fe0a0874ee7a59c300d2606a45e2c8c20618547b2e584e09ce4d63d44c5318771add" },
                { "sr", "9e633ef782d628a1ebe7dfb542e43b2ef9de01d1139677242908d0c077f0ca734580b7d8d701dc1185a0683f15bab3c98e1edd07b5540f1df48dfbdee620b761" },
                { "sv-SE", "e769263c59d91c67e58a4ed9ad19adff95deec3ded54b59b8733c85051fc1cea9bdc536719e09d87be723d2ec2cc57dbe726d919d68c00740e7534e2fd628702" },
                { "szl", "877fefbc026d504fad640ff694189d885a397475173b947ff7da2210036e0687d08b587568dfdf1ec43f914e17b3f441b9be1d4e97a7a22b6cd9520e6041ef69" },
                { "ta", "dbd1d3a9056570d069b4ef8e32a3bbab6ab8b5fa51a686720fbfeff3b1d9058fea3a919e3e9277322e2cf8a33317ee5189d4942e1085896da37c74f46a6b6245" },
                { "te", "56c686f82b0dce1a1d3960072e336cf002d88695931f4883df593e55283855fec7cb32664af28758d1840f5d1050c17e5b5b954a9575792c82f3ebc82fd3c504" },
                { "tg", "2f1adcf2fd3abe30a132347b57be91f59133c4ce234d25d5d1f85504c9002caa5f223644976748d0c91fd3d92faa215538281995bdf447bc443c38bad7ae9e25" },
                { "th", "820ddd55451c47b285e96667a8349ebe0aea764af997de2b4e7044631decbb3938d940b4685dd39766b88956865d3a96b940e9bf00c7733989e010c4f5d41cc7" },
                { "tl", "cf26cfe39ff1f3d3546e192252fdee90008dc8489ab638805448c8a32a10dcedbb60f788a1b5ba3a850331e52f70e6052706db0563b1f1717bdf9ff299b96b0d" },
                { "tr", "5b8be5d1df3fd9b54ecb27bb86e18d1fdc03a417f3051fb19f7b28e1439ec55cfba6ac9059959aae958e7eb0f52b7eaaf1a5d0889069552d7f384d1ac7d2be33" },
                { "trs", "1f76914876f15c082b180b347785b72d684ba4c78bca15ce892edd9c675a00d11177b03e962dbb91427c2a7b44da24cbbf132fa73dbde1e1aafeb432145d0bc8" },
                { "uk", "6cfa2e8e0f0e2fcbda3f6a4f99d867b70b5802d03555e7eb22dd9cd4fc719a5e52112e3b34dee54cf35f6c1be780ff27e09d5b89c2c470c809183b14d34239fd" },
                { "ur", "eaf3aef6e012ee5c3a822a1a5534c65547b2d4520de8baed7df4bddea4bb8fd7c95c42d7cb4654bde5301061fba954b437ea0052d01ee6771b74dfdd1c201e5e" },
                { "uz", "8666779a7e1a4b8c02c5bea7f6ed2a905d15b4f754415ae407418f75ef2ba2ead23ee97ab590e52e73e7d19bb2115efe9bfecea149edf2a847db5c79fc218365" },
                { "vi", "79e71c488ed3a5ab406069e61cbf902088251d5f8d00f1e33febd22c1f01e9a258ab4e6d37e178d2ac7aedfbd1936ef640dafad37b05da2d423ce927713a9f5f" },
                { "xh", "ca03139b6b212b6987259f862aacdb99b278a889b1c06b5e81afa30c424835d9b2540cfeff5e2674ad7aebca57d4bf125a0e3ebfa395b3b0b8ed8ec33d9b73e6" },
                { "zh-CN", "703b899d56e9f2571771f6cb98a88997d1f6786de273b91f10b237cae94d0e61af075b953907911bc5f37c671e13479c23c0fdc943e4116d8e745256c835e824" },
                { "zh-TW", "c86ae4a81d13f4011e73b15af631059d58f7b30bc6ad482935be825ea49e35e028852cc3e6c426cb47180cf98de6f4278e85f490ea9ec808b0c7f3fa2467d9d5" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/138.0/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "7b59872b98f1d67766eb92d58ba9becf43e338bf8931ff83934515643aadeeba00f850b74cdc8612b451072e78c329a711cbfb5edd1460bad72820d3098d75e5" },
                { "af", "de628ae167cb33a931d7adf9c33ae13893abb07a6a44c019565e9b08a6f37357f811be3e19255e2dfbc0f821c3691f62631002b8bd660d4cf5707e3b4a23221b" },
                { "an", "820dbc28f76e893e65e35cc184db844ffd999d3a3eb5f31e5d3ab2dfa7a385dfb7f5d5bb8488e3cd155d8c11f0e244f6f4bf3efbebed717f700c7954c89179ce" },
                { "ar", "112b08679826f7989e1f82c9ae86c93d068734d2948c1984026ff664f55be55d7b01fe7e79ecb27bd1c0468f2ee9e23fefe2ac0bfa7a3ff19ab33f6efa48b700" },
                { "ast", "87a796f48048876a441c7be02df88c340139cfb9bfa7c7aff8d32890f39eb02f01bc9fc4d5551b9f0d6b0ef2f57aedff9bc2ebbc8b6cde4e58d739ce690e7d74" },
                { "az", "3507d7f72ea9cf11fd316b56e34084b6fe71a64dc8a8353829d686dea2f1c2a07d6e24da626586c93a94a4d86af1dbc6c57e7964d1085ad187b87201ba343ad2" },
                { "be", "0f78bf015eb34d1a565683f8f1ebe108d846c93e847cb5604e80527d47fb36a3b266c14574fc8605e46fcc112bee9e0450cc849edee5816945b87e3ef9ed56d8" },
                { "bg", "b428beed854b31d2aa3402d68138ee1fbe32cc5cc978240616c908e4b76ea09ae8d991de4d56ac3bdee500e0c8df9d0872c25ac79b50a33de2fc3ee9d757c40f" },
                { "bn", "92cccde2cbe793f0ff4469ba4ad944b2d8e2eb24699312a5ed89815c670ade041ff248483388c5daa3fafb923932917ed8417e7c2d7862b54cf337160ca67750" },
                { "br", "e41fb7d6be2cd0e979b2bb8e553cc90c764cbfe3c534873fdc6065223e00d6968571f0f3e72a4dfc98c5aab4346ec7592a7156b66fe305f4497cca23a8895def" },
                { "bs", "3e6c6ce2b355a90ac1880aeca87a10769906ae8ef64e10f43aa1547a8ab0c9b0b3f208345d39a549402684c2c5352d1546693ea220ae7fc57216994b56b56684" },
                { "ca", "28916994f62cb9a540ec06b3d1270a921150bd5b985c9e93efae39a611ec9ecc63b8f4d24575b606080d5d8b7705ae4769e3e89a98972da9729801ed28ba2772" },
                { "cak", "d627a5bf7c351fbf4c40072a48c44a556b28f4b90fb2e429919465b939d87cd4a38c5c96ba9709629667f4f779fed265cb0bba238d3945b15d2b5f9658548915" },
                { "cs", "6e1fd84f9a4f851820c2128c536cded5d23eb3ddb2224519d46f3ff236668f6a17e7e04c98698070e290e0d484a8f88d74451de8713c39da4b4c07ae5f54d739" },
                { "cy", "aeed3a83073bbef83af87d2bc7bab3290ce3244fb0e69316966455c1703d3517276b970cbba3468eb192a8bc3bb414814ccf22d29fc42e85954aa7245edc78ba" },
                { "da", "0ba9f762bfa97a9c0b4e7cc5d3b4c674f68a9918b0f6d0a0d1d14e2d139a15905702b4cc214dc20392e6a60056107766fdb414065f5f3c6ea3476e2762c9fb2c" },
                { "de", "ba996fc74991e3148ce7024b9ba1b482cc27ee936e2e2d8c25f1cb65a6521e3a1b937c2ca4192e6149842b810775f55c8156986a681794ac815b9c2c617e0642" },
                { "dsb", "5cdfdac1145d306fa6bee092a2d0acab5e5a7868443f810f958350ba8c1489a2878070b610a3649f019874c90b461c9a95a41129cb8d68705d64e3d420e49837" },
                { "el", "3b0f177a2c3ff7e9af08f35e6451f51d52fae518cc937e2aef2204b74d58471998d16eac2a7a925aa94c49955d8eba6bfa4fbaa616e65e62b193f800f1c7a4fa" },
                { "en-CA", "bac4cfa7cb9eca24586509336367cdc4f5b7a535d974b16e0d76e22c87c66d824c3c3695b06a9b7b2d941041308f54b19341b4534f667152a6d2e1c0a5b3bac7" },
                { "en-GB", "2d90ceae61d4a44b8d824a0ab0f00e369c5b362fb12afe22481c2ba919ebf762f2130c09fb4333a4b6da5fe481f2c8dcdd4bdf322c02796872ad66754f09dc8c" },
                { "en-US", "efe09b091a9ed55d4b504235f7f70838c64d633f8e95c10091ccb46239bd951f6d8ee68cf749be701e8e6b15f1aaadee67703e4bb2f1ff220a32fc7229e0c072" },
                { "eo", "a133459a19db21ed512c5162fc19f1c1ea51c61c9d051949abb05294702c61eb3c83b7700fc945e3410f7b0b1c843b8fb572dc3347fa4cd229eafa528ed2f7a0" },
                { "es-AR", "026859a05f61707dd4cf636eff2b2aabd30beb53b988655ddb4ff6e908d4274dddbb7fe16b59577d8d4426d1a0a2e222f48370e7480587d285536a70fb4730f4" },
                { "es-CL", "1609ed214dbb51ae8ec1f8c1d0ea31d37cd149008f6305b3d065379a26175ff72cacb4be6fc7165bb6222ff83ed11ae997e5ffe8dcbcd8a7e44dd2c767a290f7" },
                { "es-ES", "8fdd02e449d9eb4602862f4d60b41357ba59b931a467f4b911d6328a5c9693e2ce4df94952032fbe42fa7b589149b2adb0571a803c08fc66049016ad68a1ab5d" },
                { "es-MX", "0186f699ea7196b108ecefe9c14ba8f63602c3be7760b9ac9abfe065855e5a1c3a987359b503a2de69b234809b486eb9d4495d27451b9a3bf1f587752d787621" },
                { "et", "1c0d42470362d64f9ba1ad82f72371e98e24f9fab23e733149e73b901fbfba31a89b964f4f3e089c4d17dfcf33e82f87ef2b3298ef1814ecc9792548a5ffd7f0" },
                { "eu", "c8ac555fe8c6a5263860bc057d8317760591eb8d2fcdeb3d4c066b3522a39c93eab2d3754777f9bbfe1e772ebea1044998661238596a436cfb682df4745b3b9d" },
                { "fa", "241714c580df341deb9eee299bfd317b7cc1ebfa3014a39ae47f77f54c7b019ec32d5e73be8404a7a41ec84a00751afa10c0bc2b192291e92bc86a639d6cc071" },
                { "ff", "acebce9989ba598caeb38afe3b20c248c5863c3fa8c775629785c369caf3bcabbeb96146b5aef21f1365f36518453b8d0b89c3bcb5d9cfc9af609d2960a97282" },
                { "fi", "a72126d118a387adfdc37adb9d19828ffa5bc99429b20bd447d6d86c6ebf63e3cff3b67e505a6988efb742c0ee28c4a1d4b598d93767643ea06f266f468a8be3" },
                { "fr", "fa7eb798aa4f996c942e2c46f7be774685f49895e50eb9fbc300bd17accfb64b1b692cefb77a216c331563ccae27eea99ea62c2ec88f5a691ffd7e32731d782d" },
                { "fur", "d49b3a73f4a3865cba93af37fad0ff7569b8c0297222a318487a70886d38884b07e54e8f3bcb9cbc2f13e103bfb6d9f7b34182cc6add195a2397b825d692ae29" },
                { "fy-NL", "4285a19312752e0cf72f5703fd14d6b53d20ea5a73dd1e2f4db9ab3c4dbd0e660dfd1ebaa9396068fb4b8ad659561d2beb5f491a05f6aead1f32624b548b165a" },
                { "ga-IE", "8d5a337d44caf339420f59edd759ef3160e397953dce7530d821dc09ab722841b9c03d3014fae7f651119fd8431d2f38b41aca4b2b699982b175dd03bd92aa76" },
                { "gd", "78aebb716366839fba278575a40057e97c573860af0b4eec181861f4e9ecbc3383ec15efa8f43fbd27ad0e5571351fa0ce73af9706a37b0a5ead18fcd9114c0b" },
                { "gl", "c7d0cd9fcafadfad70bda1c695e0f099315ba6a2d82dcf06f179429c02c45bb66285ed6de2b5fe8bd3460c94522da54e3a0287a668806dca5221a6988fef32fd" },
                { "gn", "3db4c67fa61ea051ced09013f559708e78d95b7fea0d2664bd27a52d2eb3330895952bb41a128816591d220512d2e6f29d516aa32f75d671d9441a2f90e12637" },
                { "gu-IN", "8921f93dbd6a907a96dcbed0f0a6439be2258e8ee0356a736af04f1310ccf3be0d9be664a797ed78083bbac90fee57e62c7d2f3b7a9b2dc6db20465f6c99ffde" },
                { "he", "54254669a1ea9499b7118948dcd6e7fa6f0f7f2f007a88bebdb85f0f785f6347845eec834570c83ca49a080c4de23a4d63e91430c9bb72f628889c219522a04d" },
                { "hi-IN", "1bb8173ad0c8e384a518121f3b1e0c6d873a5d6e06335006a02189fe6831ee760152fde9bda1e11c686737e0a59e2ab71a76b24039885411fb231ddf1e738bad" },
                { "hr", "d91d288d5c890e2d64962b2efc6b915bd184e765123467830e7c56425764632d850cc5e06d757af5b71f3b98d1749d76433c4f194201dc207913bb3be3b0b6a6" },
                { "hsb", "d0b6d1ccbe239362e13087ecfcfd0cbfd89b927ac4e6480695ac53689c9d6d6777bcae17dd48e46ffcfa3fc881ffb6d4a87a6f151ffe419475a47ee0b7377d19" },
                { "hu", "228f31514d4f10b8a333aad74e38c0743585eab10431d2a50d68437a025bf4fdcf6c9b1f3e854c0377f2a64576c82d05cd71d09ae0bcdb432643212fa0e018c4" },
                { "hy-AM", "c7551a76e25e9e2551d459ec993babe865fe704a09785df515c9a6148666147a1876a8a5d81d76330f285003d8168a69e37df6902ad59393ff5be9b642237cc5" },
                { "ia", "ad0e117a4a52d40ed015de89a54fe6687e0d734fb4547d736a24f0bce4f29fdb1fc60dcd1e15ad35f102fdf5e71b27f5e00889e84b399617e4984984745b1e15" },
                { "id", "19884d7f187dccd5810f1bb5ac9cd78873f554be4c5fd90f32674e6efc544def0319766923fa353121c84ea600cbce286975e7e41006bcb129c0250e964e25fe" },
                { "is", "7e05bf9837965a2133932233f77bcccdfbe1de0639b0632d73b292982abe0b1009e7315dcc3b33e28ec7bebd9f98c33762893e0ecb2fb7f23824e3db7d0d7a75" },
                { "it", "13dcd15e35e42be752c479676e9f8c218bedbaca6e4d28c7d1639e87e7ec4b9d48702b619c677c286d4da70fdbdc13d5b7956ae9eeb80397ce697a33589ecbf9" },
                { "ja", "7e319fa3d5ee81445e4224703631ab950e893d2c8f41dc4774dbc660f868e30d11147608a9cdccf6ee066267488884215d90d5d93a9fba03d81f806d284d4e7e" },
                { "ka", "b447759224aad6f3650dd2965e611c1e35c9c28f3867664f1275ebfcfdd80fa81919d618a5cdaf6882402e493be6e6acbcf9f8b948e62754f4fa2e179c0502df" },
                { "kab", "63f42558ab884516d68cb9e327b619b0415080035db07a7c643da414f2d8422ee9bcf4c37b807f54da0effd4eb6465b9f054f606f39fd43e43921569f54db996" },
                { "kk", "5fceced0f546eaa8686063d4e1129d29819e8218a45ab59a105276fb335c88d9604de59998c4210f09ce8dfec0e14b12d73552f52d95e1ea45dd962c08021783" },
                { "km", "596682a7f46af8e0917337eb7af4ba140d63ca136ee273a7cf625b58513ed27205d8b74ccd896be77e7ea6991e52dd2f0633f06d520b0ecbc5ba9fb002575e30" },
                { "kn", "9b385b7770f6778f34c7002c715de1180e38a11b7fb6d444538803163a7adab90bac65dc0d19338626c4cc470a870b4cc74e18def268a3898fc99a25b14aa8e6" },
                { "ko", "f5d4fc4aa78d980f4f7b085549856b78a97120457ded1272406c2db59c677f20167d814ab5a5b85259e4379172d8b58d9c7401a180186813fb86fb1e545d7508" },
                { "lij", "7ecbf0331765f2cde76ebf7ca771d1d791f3b7cd313d1b22e379689f6ce16c884b01ce2fd781edd504d6ca6fbb9f715b65fabec619051b09f63594d6515971d9" },
                { "lt", "d2a46bf8781121f635a49f21bf353a849a92d5226a2cbbadab511de155ecc012b2ff15d9b8d77668df9b4cfd68ac70d6800e87fa782ee282eb29e9cb45a63352" },
                { "lv", "431516aada72d1db5ee97197ed6c53eefdd7dbcfd2cac8ed2b7de48633d161f8f7ea955390dd85ace8a44a0c9e82327339bc6f0b2dda6800ce835437519daf7a" },
                { "mk", "dad506d8399a916fbfdd7c4e57a3120005127f99b21b98674110ed7b511bd250166a17d68097775f697cd256510e1aa6a9af1492d22cdb1e4f7b02e5ac34ac74" },
                { "mr", "4ff7272fba3e5ca8cf1f6236541abe65a90e00f036f1a7b13eb9fb6775befdbe07acf3f459e5abdca75aa4d36b00024c2c40d22e538be2677f03e347528a5354" },
                { "ms", "349eb2a2e2625096ffb922d35a586f8b103b0de5bb0ee895261dfcdfe970d372c29b6e657fe0d69c20e835ba29a2707306f05e16e2c8784993b44897a237b431" },
                { "my", "97a01b0272eba862589d1b5e078d96d78b62126126eb061305eb2123506bbffb03aec38157d6c4ef410779b0e8763b3fbad7dcea495e0f1d77d38313afa23ab0" },
                { "nb-NO", "bb03f07bf45f9be5216aaeb09bd0d28508553626dfaeaedc897477d18575c217691590fb4464d5b9c3c0765fcbe9490aba1e9f97759f32292717d06cfea24590" },
                { "ne-NP", "0a88cf0f8d33a531ac3a35faf60797b1175ddb77939ccfb60a3ba07ba566cef2876c126e4c856c1ff63f17c109688694bf1af769d3b88e89b33d00748ec1b152" },
                { "nl", "c62bb056eaa70b479c6de5550f6e42b888fe3f9563ceff24175fd2f730c544e511e6ed4c5c780e1200068199439d11fb6793385186ed47f8238ffa5ce14ab373" },
                { "nn-NO", "7ea9904c7b06958ecb5948da132d5ff46206b7b6bc28c6516102e0004166e2dcf0bfe96a09defbdb8d8563d7d17ffcb3797b151b4511adf68c754b25c0f1c1ef" },
                { "oc", "c636c9af73a99eed2742fdd5ca47e62339eb069f6a556461720a4933dea18c840b008f7fbf4b014f91924c7d4896ddb7ecf3472580ac54786350e8e7caf7d3fb" },
                { "pa-IN", "018e5bad52adaf61053f37325d3421b75d7e0f59ec2f83a014ff5cca93e4cae318f810559778cd57594e7098fee25f70a6705c91a6f78ea554ef809409e7a27a" },
                { "pl", "4dd9a42ba40209423252fdb43b42847f7bbea91c36b67fc91e28eac119b6e19b7a1d98f0584b22b3761f55e38c48f81f63480314f62dedd78bf14a0008e069be" },
                { "pt-BR", "bca81a51f15dcda8239268d4defd59738cae86a1d27a11c7a581432279a2d0a9ec0957f694e0025f477b2f21938c3b0f961bb5bb309b5504a498ffb25fa82e3e" },
                { "pt-PT", "56e435299bf3e9ecab512ec4807522f2abeadaf6e5c961cbbd4111f2b5433d12d1b0ab8edd54322faf55193b0f1e6f4b6cede017f0e09c0591d75dab31292ede" },
                { "rm", "731207f349d67406485f9155c75ddc9d0ad7d976bd8c6943cf85351a9d40600330f23a8b7584aa23196bafad6be15beb3e5e7991be679c67e5d5ceb34b16befc" },
                { "ro", "685f14dd7bd4435bf3038655bb1eba297279622412d0abca5b7eb8efd846a890912ad33cf8881a4c1f8be53e3497b6dd9a9d357bba10d45bb218b4839a361634" },
                { "ru", "714346313be3957e6638e02f527c8d90ac13758d7add5bd5fb5c0f5ba5b90caf410594e77862732b6abd728ec75355bd17589ee0e5bb7f19fca6aae6a8219b19" },
                { "sat", "7e59f88d6007692ff196534731283d96b2edec6c92043dfc845033900d9a1b7aab7a4e975d8809e117dba9cba88ddf1a742acf3908d48f24675e8a717fd7a151" },
                { "sc", "38f02b91cdb506b2f619f0dd403ff0b46c958096fd2cb56051352a07e4de305dff4e8d030755872276d4efc3264c12ce9d9bc1e06d554ba36835b402c04639c7" },
                { "sco", "906fd93cdad89f189273db46e0888c2c8962c9da759b6e1a43b0e4773170ed15e552ce3a3eabf6f26a4b733ed430633021eb08409aa545bb13b60099742e2dcf" },
                { "si", "60b32fa6912da7e6d65c4162c8de482d720179ea7a9b739d1abb70b9f80564dce7832b8c757ccaef6c387da603ffc3341a488c22a3db846e07d8b02961a0786c" },
                { "sk", "d8b3e442a58f5465b613fa932da5135355b2c20fee28965ea511a36c0d1bc549583914571db1c1b0872bf9ee505a4958c66f5880f87e652121155acafe42e1a7" },
                { "skr", "693c453388fe10e8512de00589ffdd29f49bc2bcfdf85ed6bf8bb0b6c1407184514de6a6275b7941a6a8f0c491c0b6a3ea46b45074b9ca8dd1baeeda7944bc4a" },
                { "sl", "273017c3986e756f61ca46480173251c7b86e9ae7a211bf17a178add09e485b2a47e6e4cb17d9c2b68dd4c52f74327da2859e889708fd505c3d04fa554c1ccec" },
                { "son", "84e5cfb5997329da4e63262f205f5bb884f63fb6fb7362031fb73ce41af7afb75660e35274d732a7ab112bb9c7288bdec614e24409feec9326fd0035dff71850" },
                { "sq", "85dcd7dc7d8bf078ed88c4483846510e64672a7119b03792d8021d7310cb576cdcdc705867e41c9a8630634210294009087cd6125f7b18d6e10c87d1569f1ed5" },
                { "sr", "5567ba536064313146d4c44141157e621b18e5bf078f38583c76a4dfcf3afd180f8b8ab7ab0e876d857f0cec697dbed95d623fd4191be2656a950a8d55b7ab8b" },
                { "sv-SE", "4c7b79e65fd15660c42d51a4acc6e0d6cffac3adca12ff7bab64359ef7115f4c5099a0afd998e517ffba2f27a3189aa1f6b79eac0eae3ba0819f8bae2bc4061b" },
                { "szl", "8a93a31784c098dd71bfb36ea59f279382574d63671818bcf8f5f9f31fd1d6a71571475b0f64ada0208989bf836ccfe9490731826c95099b9f114e2f447d17ff" },
                { "ta", "7794ad63c5fd75756710852c30673d0f1fa5a18f4b7cc137c75b22620c0d90666014f05ec52b84ac6bc4b7ad93798700aa741e71a0299106ce735c42a0e5e0bc" },
                { "te", "4de0f96230980482156445229c8ef09f08a8cc668bfe5470133512bffec6b9fc9f9c70e7f05291df62e515a32c30f80efbaae727b6eec46d14dee3c6b63d2a85" },
                { "tg", "771af80ac7e21182631522477bfc3142e4d9bbc9dc368e42eb9ea3181dc82c170d7f049870917a54ec16ee675d1d3cb5737f3fb42d84342e56b1a26c6f8353db" },
                { "th", "15f7cae0d41e9b6b758667e534ace961cae5bfef042ace4480c65a477d2b205d6eaa22ef4420be1b45f59856dda7d36c612f3ec7062e160e1f20d3d0511649ff" },
                { "tl", "b281f7776dc6eec7a29ecd55fa2f83639e1bdb01a39dcb6f68c7e91c1bb61b978ad7ab04da98765194a0986a05a541df24e59859da0a0241b201adc4bacf4f61" },
                { "tr", "322d5ea50563eeefb1f45e2e4db84ce5d8b4744fe18e198f87e0a16ecb76d054fbfc8a72dcf99fe4523f573335a4ab9817991e9c133ac06475cd720587bb7506" },
                { "trs", "b9b9b6be27c2265a563e0f219071f55844a83db38a97929c4e1eba61fbcf25946bc5f48c9ff92a59b82f81a9955cb3ba3ce1c18632800757464ce004f5fa37da" },
                { "uk", "ce6857c4fb987a81f2c579384053096fbc4bbc8011f4be3f5bb2f7c7262ddb5b91edbfbaf2c468076aa31e1d240de5f659b1d231a5f368efaeb4089324ba950b" },
                { "ur", "5ae12e494419ee519b15a783e22b4b61413ec5ffcaefa56cb541ccd1c228b413fd0f07943440da0d708965ab3e4fec918bda966b667434f125edde1f9a65113b" },
                { "uz", "d0f96999e23cf264638b4ea15777562e8f9931fa3770fa774e442271910dbb00e2ae52f8cca75200faa14b3ce8f352f8331c4730935df017b9da46b3d39dc249" },
                { "vi", "3729196a3c6e702cfa3ae0e275b44efe05dc8447ba5af50ad260bb13dbd27a0fffe12b37f8c893a54b06d9a440cb427e93a553b05a50ad8c651767999d77a5cd" },
                { "xh", "038f39c079535061c73c71958702e22a8faba5b8d1f2b0312aeeed8d19fd04c8a9a4f9222fa9c7cf80b1fd48125a763600f46b1992f13c9db82d85d20dd6c43a" },
                { "zh-CN", "34dc92f6303346b0282e98ce459a6c6f391eb7834e4474165359f98dea30958d17a5fcad5aec0fc6b0d98544c9b7bf97086a6ec4d268fee483b4d3e784ded568" },
                { "zh-TW", "dbc870e657f88aa9da908b9c1d11ab21d8055d3eeba2ce9db245ee49d8a59b5d474cb173386e3852b4869ee7285e23e0a03ec29298a31c793202bab1f3ff45ea" }
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
            const string knownVersion = "138.0";
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
