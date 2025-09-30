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
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "b7427774c15dfb34b1df1123f5b3a0af925aa3956a0aa1ec2ce4c5c1d0543794dc0ef2658876fdf9048f8a246960d1cfdb9142e620dd2282ab6dd9a8c0519982" },
                { "af", "6b7d2787085ef02525c2cf9820f6dcf865802c0c518ab44edce88117eb76ff529aa1148c6ff34e8a3d6bf69a13a0f4c05f48c1a9bd308909b01e7a972ce3dd06" },
                { "an", "782cff4c3fea8bd24ecb90562c9adef07a5416cb9a58025779d8ce672407520124f6ef2cd3a083377230b393ca1014b8274d822b1e38d9daba79c384ba263235" },
                { "ar", "9021902fe2cd325d5cb99d5a0e7d48d3fdfd74218826bf71041cd366a35a43bf20c9fa176ca557be39de6b481ad4c4c723b8bf902f31e57bedbc30b5966796ea" },
                { "ast", "92189f4de088f9726bd0e5773fff505a53a713918c69205fc07ac9c41383bddf95b799a1edc16464bf3da3fe7775a6c33defe93b642ac427793cd46e7065f3d4" },
                { "az", "cfe761df6c5316ef3f917449379d3d13daa21df8c0633cd85f4a328deff3bdf46251a0605ecc7e9aa20a52bea7bf86be4ba45ff35d975a1c0d13af6b47452984" },
                { "be", "1444c22c6d27361e208d8bae1f5d54e5753d3203a413da0b4129a4e6dd4af886a48dfc6ddcb7582a99925dcc1719d361a46d59be1e117dd697ce81e11c92ab4b" },
                { "bg", "10bd95cecb82c69bf8594cb2f398a86d6f95a2174c3de1fe364c32dee3b275108386a3817448d9d53e310243b3be27b198b2ac0c57bdbfd137baf74ac6abcc33" },
                { "bn", "bd1b217a81a074d2a3a82e265fc76cc80e0d8cc05bc6890636d222fe12079ed81820e16979b8b310299b4db5485cf86481dabfdfe95b08a0a916949a684cf639" },
                { "br", "c117f701b1b425c004c3378b80c317c0f9dddc70b308516c0380c0c874ae69d94249241fb43ca7734dce571bf11c1b7b6c827c2634412f3db49020de6d6f2b19" },
                { "bs", "528f824e673d90bebbeb65ed7d511d3e404e43ccb99f6c979dce720415d286f1d223b48c66a9f5b830faf9a56e3b6918dadafccdd031f8789ab9d01568267c79" },
                { "ca", "26bdef71896a2a13e9c3d5fc3ced653f2d0f398906572837bda45b9b64b1234781109db83eecaf8ad7c9b28492537bce4de05ed4347a9a15b8ad26c5e5259d10" },
                { "cak", "877902dfcd6cad03928ee379a8f26e08f1efab9a58d7f6da311dc3f18a4590bd055ecfac8634b038cea6719b8943bc2393897ee11b92a18c1339622d0f8a13f7" },
                { "cs", "4811eb0bb37a6acd13c09752b0029e4d2a3aee221ab14268a0dff4f388d0ebc84526b0e1239d4116d25a81a49221e2d322e3f923a67383ec4af063ca51efa3f7" },
                { "cy", "31fa28b356ff45f7dd2eeed37c2270d8124ddccaaef8eb8a1ad5b9240d9d7a26e765a53d9d5725eb60f32a8e2670001df7009d024d884cab38e071189c73a875" },
                { "da", "e8f3053bd7d00761d41b7b056e003a04cb2771d103754132d3e97e0db19d4ce71d424138a7cab7e5c14f194ad54a12ab6febfab15a48c7c0e90bd86c25de094b" },
                { "de", "646c4555d3cf586e37776cb185cfabcc6e76221cdb56c229a2437eef0c6f1b4588bbc02ed09a4fea5f21fe1b935e52c0b17165fa0ba60b0c5c6e108cff12b81b" },
                { "dsb", "8c7b7ea8d923ade7613d4fd59fb61e113c3a32db2546678c35495f4d8b0e84c33a8f643c74ef8633cda3492f9d8d58d2697411958d7f58f435162c0335598b04" },
                { "el", "4f361022703f2dadda3298111cf20e0b29d6b4f6bccebbee0d6e609766f350b082bfececa513a172f3ce6f9c8da4b3769c0c1747db9bba199fbcfedb9b9ef50d" },
                { "en-CA", "d9a58ea8ebe06d1db91720818d1bd0734a42b13a59718743924d28c94ee164406e0f4793aa2b35e53cbd7ebedc9eb7e4b8b425863f10069ad6a9d75376a41570" },
                { "en-GB", "1576ec806c9528c96a872c5afaf15a5cdbff85db2bc58c98c5cdff8b7fa6a3c1ad5c1c559b16ffe56983e6a81fd984d4b4bbc217e89bf2c1ddd9954c41c7f429" },
                { "en-US", "696db68d1ffa5df8b097731b3536f932c9f6e802205cf02b983e4ded7cdc481d41b9e90fd653f92897c0519a351b419311fd6a72382b30430ed96209f0bd1690" },
                { "eo", "80718c1104ae390be2fb1e6db1d10ab0aa1cf410c5db073e4ac7a7ce9817075c2914b5c433466d95e32baa1ef16ffbe8f542fd33abe8e172c356a806e3438eb0" },
                { "es-AR", "badbcc2b5cf945f5ff18f78c293dd00c54b3c97a9c60d11feb0c6cc4551a4bb9b0efa48c7b8d66d96ebd4b68a61a57787df2f710977a06b08cc6e1883e94abb9" },
                { "es-CL", "840777e8b0c61c00abb9e41f466e9b5486a765e1dedecae2f05cbf8a5a036bea7fc4ae885fa50980612a2d996d896b087c3daa0ff78a27ee9a6aa4540ef4fee3" },
                { "es-ES", "35325a53371cc17afa2d26abdbffd1e093e4de4c5b6cebee7f76db0fd14877678ed17c38dfb9c4f42b557cd196cde60605006d30beff70d7a33f860374d4d6d0" },
                { "es-MX", "acbada2c6c8371544e7d30f5790bd48cbc11e8ed35b033afaaa6ead3ee47e0debe917d83100cad7b9eadf7e259f85967ce4fa0cc8f2bd4e01f4b728f73382798" },
                { "et", "91fda4ce535cde12933d1150e12c3ea399817e4c22c850b62571a62130dc585ac7cd8cddde48acae2a1585938ab8e1fe45e53c0e90bc434487c2024d1ce1a920" },
                { "eu", "27253d105a9e777793004bf99c31a908e5d41ea38381a3cbf36fae22995a10b02bde6190a33a973bfbf929f7453e0c8fd5721ad8c799634914ae8f1e90ace8e4" },
                { "fa", "abedf556d2a17f772f3e08b58853211171d587bf9876c0cf32a97004c8ebc2ae254171b5ff7605691edd8c662f24b1846737e21351542a4c658d0a8ed7d2634c" },
                { "ff", "ca3a2d7dbee235241930388b64ad88715dfc87bab6e7edff14eff1522d9287aa5cb456baa3f7e62d8c7ff12b1314cd161b63f564bcb5d8cf97b78276a47d2821" },
                { "fi", "8bbc5381aa8f275e8cc5d15292af2393824bffc6c68dc329f7120f75c2a2be18af08584c17f12a2f9f702884127e076b2b3dccb4048b283475faf214b07cda45" },
                { "fr", "ee930ad84b38d539f1decc5bedd4eaf383b0e2e2871c5d416bf98d0b06b724c782e50adc92611a1939524f5a20f6fa3e3a5ce3161c359a3cab9a3d38908bca75" },
                { "fur", "d954a48473191dae1e36b12bf618162c59dbed0d71d8dcb303d21bb91580149a26998c8096ebf0cde243b8345832362353f4071eae6d744f03de0109df173ba9" },
                { "fy-NL", "e8c2cfdd67af53b911ac723063b8aae549d7c5a0efae522e7497ebce7b3e9533e68d6962eed345563f28f6411d842c84b9bfc490233e224d9b088bc9c7f475ea" },
                { "ga-IE", "1e611519fbb94d85ac68ba4d1ebaf3f251588dc3062990e903abdc8763e1b015149854f5c8e8c3a379d0182616f68307d1859b2bf2d71bb2d3f971a3803db089" },
                { "gd", "c439ab2f5063472019cf18f6ba0e3b8b6d1c550789942d0ac4de7d7f83552bb9c2c5739b79938ec7591d10842079dc807d4fcf56a1118055b40f6e288d44863a" },
                { "gl", "704d43d4d3fccb1e07c579e78e20bf3eeb46275d5bf33aa910a05d1c8dabe09b536c4f1e83eabf3359d57de1f21e2d254c8c8590e38222813665ee3437188d11" },
                { "gn", "173b5b661f77780e8ab89d7f36dcf60c2a0e3ebb834ddff048a7484e144a6ed75f826e30fe548ba64688a15db96c2cb3ed1edc1c2c8d47cb41b8656af4b03040" },
                { "gu-IN", "563ae67456475d732437800920088ae4212e2e7134fff9dad167f7f098146432ac3c051d56ca5ad2a07bb620a6a40945b0ae0aa7e1be8f638eab317aeef25542" },
                { "he", "20869824c6657422f60546320d94895a1e341e4b0b8e89e82d573179fc2f9d1fce7838f774abeaa7e97d485830cd8228524faffa5ca81533295a65b36f7c5ec9" },
                { "hi-IN", "e662b878bcb657a0102e6da9df3b91c8e6bcc27a84d728fa946c81670581e558b1c5ea812bf6cd7021c354b5a82bdb4477d9bec57f4eb66e473931b712752ed2" },
                { "hr", "ca58fdebf03cf92a9259450f4a4395bc29e4a0b354179fee2f2587f20b0f7d417db82c1702fd67a7e2e2dc1357e633a3f243c4d2667b1eb03bb32f8eec465813" },
                { "hsb", "f098ce6d6e709ba42a7389db6ddda6f5a8f4a1a67c93cc9f8d11079e7e4404c6a447ed7d7b3015e64e36e253c8591b9fd2f6da940c353ad26476976210fb7d76" },
                { "hu", "2f63939e17acaa87437a26a452e5d894b44615c3803efb19e215bfa1ec04d922ee871e16832657171c25dbe171c92c0d18b87c603982fdb5773c871177e5d447" },
                { "hy-AM", "4fe89e0e73c551cc025867680514f3576f99fc9b46810bb2e8172cad23403f5119eb368f1b5ffe525d14f71b840191a5cd8c47935fba9a701f1ed2d8406d3284" },
                { "ia", "a98e6862c0120da9cfa3e063d443f19fa87181d846bea431d74b4deef0605aaf787a8d2978c3d6ec892297e33810bdb292b3b8c88fabeab811828dd577e7c84f" },
                { "id", "b0971319894796460dabc3039406a1aefed4a27ab00c2e7ea53d67004d66cece8c32923b8a8b720e1bc24f289b4520f361e420dcf8447506deac1ee246bdfdcc" },
                { "is", "03753e1c1e63ab591898365396f447384cbf8521284d883f223afeb1e3b35367279528c38756f8f468cf5ec641e78b3e66d582c2003c36f17d52f5ff9f46db90" },
                { "it", "445d9667f50cfc44b9eeebcdb9456198df9d63bab14d333290660dca6f6db5236c8c377f284a1aff9d0484cdabd1a332e495df903a6828ed8b7f4542dfb5ac4f" },
                { "ja", "a48b526c7b3475301824a864c89d23ba116298c08cf12279a2d6614ca6f216291602f7af4d887d0b68771b5921786467c30ebfc21f900fd065221c3b5947f54c" },
                { "ka", "5675eed4ea83f7c0779320928112521bbe7d820bd57f1565c2098deb8842c0e054198d79e71462d9a68afb7149e09482b9d45f3549171abb9550fc2135617c12" },
                { "kab", "9b82d72118e4c582379aedd1b7a4139a640aa58f20180a6ce18f05afe83684c82e1b6fc1d9c816e5616ca0660e7a0a5e86cf4d3dda053c30bfcd7da4e97d6186" },
                { "kk", "9de424d391a5bb85d66bd1bd0ebc498072022ee67f5d8c432d2d82cae4965cf9acf24228951341cb6c89ab590443ad2eec57acee344d9680bb1f6851911e7853" },
                { "km", "3c874228b31e4cbdcc9e8ede344324845f0ffbd462793bc050b974964db87f3e7505ab9c4d48c1cb2feef546ee73e099aef08cd3a87e0f0a9a466ed02040238e" },
                { "kn", "2f018987810459c2557affac5283240f25d38ca865e7efda11dcdd494d269667055500d4cdd441f6397427f0f03e877ecd6044d5e613b2f3872336fe631eb307" },
                { "ko", "7dbef3ba74ab0e8865a7fc8c0b498baa9e580a5bb21e44017c4e62d298205fc606829f1aedf82381d02674e8e07fd57fc45d6fe9bd5f575e959727db1f4776ab" },
                { "lij", "9f8a822356db1e2594c06bb7eba50d1f9daefff06adf602c64fd38575052d1bdff773a9a3586bfce45f3d1c8231323f9c72a141731fba1712fd0c25153cb8ea9" },
                { "lt", "d90292cd32651d42495f0c35beef2fde6d4f3e5459f62505f5a13da451e49069d3896e3c5104634605762b6fc8c2ff4788bd62da7a4ab3fbde1675a124531494" },
                { "lv", "5e011254f09b3dc5c4d11b2d2fff60f57317e02f756e1d7590271c281c760fa245d31bdee2f62003265fedc489f405312e76621ec11d389e9c92026582d2576e" },
                { "mk", "0b9c2c73ad700fd41177ff2baeb599147f866c358e8369620b93b1664fd926ca3bb77ef342002220cbeceb56fc025578c350f60687ecebccebfac88008044414" },
                { "mr", "c7fe8236e83102bc81c5fb645b81e9f5ec2be3e43751f1c26e45eb9a73f1595e28ee8868b8323419ced7d0096b6bba11d56c0c3a7836c2064a457c3b8807398c" },
                { "ms", "f70aac53da3cd9712b53889cb84e8d6e60c4367912d70b0ea98024c92502bf12c5450ab23a7bfe7e8d17466823238f815ec1d5c6facb398aa4c6d6d25142d284" },
                { "my", "eb49cedb0342657345d5357635ab61040af98a8f638072b352ec28bc719913016c73bd9c8463a7d2d183fb6f04641e985d4f370a40a4a82062558418917ef785" },
                { "nb-NO", "7ec3516fbd67f5e1e9e22271d00625a39d43890bcd9210e4f07f01b12b992109537536e0a804d5ff9eb4a7c37003ef15ba15e7d703f71cd7926b339a2aa864fe" },
                { "ne-NP", "4d481e0409b708bf5b5358ea7c6b4b760d7f8160364bbbd4fa79e30d3ff1c58045c449af469655ad83345d60f3f79544d997c1bd6c5109cad7bebfdc5961bbd8" },
                { "nl", "ebc247643eca3074daec0b991fd9e6d78b0a33cd737d14cffedde128a6c7fe777a37ebb47b35e1d560787d21647a2816e1eec550899d559299125134d9182a02" },
                { "nn-NO", "ee08cb50fb67df220ccc4f1223529070c410d9bd7550487b14e955c41aca23df4fe76755c65ace200a9ebb1712202636c9b99b2312452d1e45715e53c0f8bb00" },
                { "oc", "5ed14773385a5fdd9114d00cdf9921ab16bc367ab2b5e33ed601f04a3ad0d6948815fecc2cb136f402693a1ab3b6c18283b99bcefd4d39a11749b808ad299bc4" },
                { "pa-IN", "3ca2077bfa7ae334e8d9286e7a1b476693cf516f065c3919ed28a5fd4971d0450ae2df53cd16f71ae8410ccf2cb17acd8fda3eb84b4ccaaacebb5972768ca039" },
                { "pl", "5920c4a6f7d929082db8b33f5688014aa939c75c8a52de9cc3e99046db109987ffcd63f1013894368788e927605e1698276505d89ed7e16e8bdaa991f88f51f9" },
                { "pt-BR", "cdae9ba2a4f334212dc780161995924f819c17c50447672c652fd29d87381221f2af9fe96714a40cac1e9d8a42572e2db622009845797e62ddcaf6c0d92180b6" },
                { "pt-PT", "6f03c7e231ad5d92594d8bf6f065a031ce857bc72c3c4729e4b865df662315b1239ab3859641e7960d9d2faac53aefea4f31ad70a470d3e4ad9e8ff589417a62" },
                { "rm", "43c0793a8b70a875317bb5020dfb454141c105b03117d19cc7a47c2709714fa8e2028c7da369099855555064bb6a9cde266ca719016bf8bcc72d0877f04025e9" },
                { "ro", "5918122e55cc3166063d21462bf7c9d6af20160c1f6b6bfc546395cbc4958510c8b20ff7081427872a044972c2c8971ba071aed061d55f25a2ea12df88a7c96f" },
                { "ru", "064c2c8ced17fff45bdc381e7c69b3255b63645774bca81419a23ad5d0af22a6aa7d3ebb760b79ff6425745919d0066461e4033b8e52023fbc15176124666e9b" },
                { "sat", "fa9bdcdaa20d295262c7f5f83bed5c8cad9603d2e085f20936b16180383452a230280c993824c31ac4ab995e89fe6b453a40b74098a592e3111c785a4705292a" },
                { "sc", "bc76b155df61b76f66486a9276d561c4a241a73ce5e75e8f194b81df1fbe6083132e8704331ebf5835a208304315506546b78ffd96a485bb536e951be75a5c04" },
                { "sco", "b51672d7bba2b4c3a5b2f455e139a1c8cf9992f41fcd9630f8a8816eee80e10c7804f67e7280a267f498e8861dd844e8000968a2da3e063d747f6831c25d16cf" },
                { "si", "e9654991bc8bc95a83d31bb42dd6cef2c0bcab1d2521d5c2ddc5f3e3a6d5017cd0adbc9d90e319a46cafd2b33e9ae8a1de2269e9b955ab8cfc22ce37ac4ca898" },
                { "sk", "ce8a161ff8871f6df79dc3764f0bad4d2be8c3aedd790c82aef93c3fb239a27d86a862b1eb7916ae3138efda5e0401c9a176ef30c2f6a87ae35dede5d37e5725" },
                { "skr", "39a085f670939336f6c3022f6d462b3185721a991a8b4372d014f54a1f4ca7e49333568fc1d50e4679bc3933d12cf2293d41780d7424cc0a777f06da4e3ff453" },
                { "sl", "d223fba05db94123159e51c6a70204bd9153a065e625395d164206c532285a7edd3c7ccb557c291c373ac251fd37ccb234fd8a789b490b3646dade87b4332060" },
                { "son", "c51bf766f71d319dfc253b2fd19f4ae4dffdda5c9e0c2c7393a4509066dbb43c4b002810bca3fa70bbad6d0da95d41face2649fcc465a12f8017166c04ab77c3" },
                { "sq", "3eaebeb0aabc022f6e655be6920f585cea26c6cbfb5918ec1b07c0fb334eb70351a55c9a9dc99827113a656e340e3be4e35a6cf3c616a404c882b2385c6d2dc3" },
                { "sr", "e6d269879725e8509fa459135fb5430b36b0da39d269d1f9122d3f90dc62cc2e4a4ff6551af1ec98c14edcb964fdef84aefdf774a703bffb0f93ae933b7abd66" },
                { "sv-SE", "06ff6380ea94ce5ae33fa6f58f0fcc60b38cee2215e90e492045602edece6a16df5b006202797968191801362ff129b95044d33709b108923ecd24a8b579ebe9" },
                { "szl", "8a682ec51e90710fde924aa2dffba50a2c5aa59a034df7837d73edae273702867839921e074de66c1136695a05989db412b1e38ab8b5099c2408510d9b772cd7" },
                { "ta", "1821cc492eb014bb52516675888b50376095f17d13202054942be9afeb424131998e3918c904c3a958eccfada709ae3e0bd98431544726e9738f8b364fb3a734" },
                { "te", "3e62794dca741a093a362f1424a1be2f8a530279fb143808300d753383d0921bf62aac1b6c52bc9138458d984b8ac61c1aa7635e4ebf31d2ef7726e2d9a8ef97" },
                { "tg", "4d50eae3c9004699569584c262c4b64f88a11a0201f87089af85dc94300ff446151aea6201c492345f45510b621b41f241f101b8e96d957aa596f4475300661a" },
                { "th", "af6a3940e98b6560303eb3dbfe0a66d84eaea7c3550ea7385fdc9e0e3b2e82a9eb6604935205e97da286c403dab87a0541d732528adf65d751c62670c05b6db2" },
                { "tl", "24bdba642e938ea619b76dd1437c3d1c1257999abd819b5f28dfbd77bf6d6f2aea151d736d35cc421aec5969d781f6586e79768c0cfd9ee567c4361a2f2e7b6e" },
                { "tr", "587188ada88993fe97a73405ad2fbf2f1ebab7242796f8bae77ca5870a2fdc8b808c59ac5101974ba138dfc581204feebe75f516acdb50f71445eee034d61cfe" },
                { "trs", "9b55ca2656ba281d7fc966165dcb09046ced86414f266235b9fa040290787480255f0df67d1594e9a92d5dc333c17ca4ef203d28880057f092dd86923066fe6b" },
                { "uk", "930b896d08156362ff1c704e5fca5a20a0001627ca53705afb2c5794f3b481892953bbdc6b3223c33c33530ec75166e7aa511fbd12897ff271278d7a5e3060fc" },
                { "ur", "7ac7d608497074bade42882a005f1f3e8a95bfb693fc3f8189b2f3b2ed9543dc9baca11acf5210a2d37b22748b7cf65d776ca32903d77567f071b2973602e2d3" },
                { "uz", "f0901d6dac5130f55138d83bd9657da86a83538a15a2d1d19699ad271f4a9dcf0f8b6049571034d58cfe32a14b8af5d06bf7b546eaf31a5e51375f0379b58525" },
                { "vi", "850184ecb532029082047b430176ee1a5b953a294b6d2501d6a4dc9e2584aee50b21ecfa90e99727629e053c111eb910d9b4d455f2220f83f63399fb13f3abc3" },
                { "xh", "6f9a3c9a82005b04a08d9f82e5cc2dd5b571e9bec154493bfb371b7e055f9e23cbbe64a4f7c9d3a399de20e218e4358761a32791392c3ec8a50c2d3ecd8f9d88" },
                { "zh-CN", "59af00e2ddaad98df9db0a1101d478ab87f7fbc9e1afbbecca7f3aa754065b4287ff8a4985d039dedc3aaecfd84d4e87724672451d3d133bcf3f1da838bf872b" },
                { "zh-TW", "ce211c1b66c09167851f4821567e56e8a50d9db564ae88f3f8d5cc5b4ec4eda7a0537c7dd2a9e94d31a3fc7d272348e12ce260190d127a506fac77154227ccc1" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/143.0.3/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "745536db29dc608892351691c8649762f75a4022a379ccaed412577c17caae635f817c926ce59f7abdeb17ce5fa9bbb19d60fb0bc6045e4742a5699338671a39" },
                { "af", "5a3f67cced26e7658dd051fe09d59fbe849678080a81cbb9bce527bf030a3c5dddcf2596182d708a457ddbc27b678eab21d2013a997ab1dbc106252513293138" },
                { "an", "424c14d75d37a3bb8db1781cec912ff129cde590b2b376a4b5d701f82298abe68dc6d82d0f59211c6da8bad936e851fba0e05b035c69c265d4454eee9313d528" },
                { "ar", "35e2bf57b3e8979b842dbe5ee87bc8509cc8e5de2b25dd168706891ed266697b2459b9664136d6eb182467eb059667ac65a9bd9b4f13395076381100fb6be93c" },
                { "ast", "2673e7898b89fecc5a23b16067cdd75d448904ad9c7c65107b6f961bbbddc820904ce29087b10b296cf44ddd4bee4e8a15533ad1146bf9d46dd3b620b11c83bd" },
                { "az", "4c461660d9a8743b151128316e8c9bf1f62f8f67c6826378088746663b05283a289880308822c095673ac5eb754c2d7312daf4cba650b3b40154616e73f7e525" },
                { "be", "6fe6be77257e43c5e76a9a11d80b748b21e9ad74f2e41b9754c7dc10818f27e11484dd0f00605b56fed97a833a2e8bc60708d8bfa77f4fb410ef3b5d1b541124" },
                { "bg", "2718639db4f6607996adfb955df15002a41c9c861101ab0296646284026e3cc9fbdb535b0e3618d7df20e83ac9bc939b951477dc2fc9dd9e53921716926aa088" },
                { "bn", "d2046bd5c5d1a41b04e7259cbe4959cc8125acb75e3e0c5124cc7ee3d1047cf88bfc9e581b9f91b0f9e1bc03e5375ac7f494db434dab5f222cebcbc333cd1b0b" },
                { "br", "b2b0b8c51e6a00977749badc6f2501b06f8624ac935598155cf530927bfc1b21a970ff2766b860878ae2e450dfd32f1086758101ba91ae5493738f180013969a" },
                { "bs", "b9b1c12680ec1073861c7ebdbe2c0e1db44220257a732fbc24f16b7ea8ca806fd0c23d18fe79db23d22210902568602dbe584855cda102288d385dc5e76a49c9" },
                { "ca", "414c8a4bbec0ee4beb83c6497b8fed60a62689df00145ee83b7931c9dc32b7c760c13e59a349dbab90308f2758031d6307649c929ef6f0efb7ff33b506bd5cf2" },
                { "cak", "a94bc048dbb79eb19835961b98ebac80fe82965365ccf1b0e7a51d8306a9dbb585c8302eec10c0f8e8aa417c5ec0582b611ddd4dcf613dc549aaf9afcf7764c6" },
                { "cs", "bf81e9479ac5ca50d491e5c3fd9e979e7f82a5fcc4e1a58fecd2a1d91f0ee78721fe799bae0a1e91067e43a9141bf0d218d654e79e37555cf7af07737ea5b2b8" },
                { "cy", "64c885307110fd0bf91d5bf91446d9f8853f1a82a9358bfe3f9775779d59e4118f579cb4cdc3ced08ee35338c5f1d736235d60de945f3fd311907c8feec065f4" },
                { "da", "3c2ee3f8c30778d2833979058ae365d215e3f31ef45af929dde8b588a08a8be249a3c9576db9bcb30892271b68e0f6ed77e7f9054ecd6791c6fb3334fc14f2ab" },
                { "de", "0c5b52e1a28f4f74fbf6246f92329b3822f9acbbfd3b66c6ce5071f5ee4fc0e02a3f4fc30fa232e7b68d301a53191d11365e4322dc98f50cb15f3035d00ac109" },
                { "dsb", "8e761fb809aa577ac61a6bdf429197fa4091c78bb119dde202f726f63ab4123870a44ef98a0e2aec8e0d967d8ca6cd7a237e6f22ab2a2a1c92bbfcd7acee236a" },
                { "el", "0c4ef9e2aef9e8506b5c53eb6f5bc9f4c8b781393ae5abdfd68f17b52ce4fdbe74cfc8792e4b3e341101820f80d2608eacca1530ff18c767f552e96ff50e2a59" },
                { "en-CA", "123cdefbe50920f26544b74ab58c770366d40cad60dd2f78935cf89dba43db44ad3adeca12280055b86155d72d2e3612e3b9eb17ec499852fdd6e186ce363b2d" },
                { "en-GB", "19f8fb940a40b110e773096eb6f2109b3d28885e72b6238d9cd775586f516e70bbe39fe820d96fff87274647d972487d04d856c903b0b9bf0e0f3156cd02c8ee" },
                { "en-US", "c3b5fc99d4be2b6444a7fb45e8df12a41e2436e41f98577a9ff6689859489daa42eef0922a2f9f6be0085614fe2a50304cc9c05e7fd0b75138d4bcb201a3e134" },
                { "eo", "9da25effe2d29d93e8661a74372677ed2b5292cac5c3d4c3c560de3dc8bd05628b2fb9acaa63ea7a53423423f2b8bd9daf896224400288e50aa2df2c0380b614" },
                { "es-AR", "b3e721430de817e13f7948eb013d7dafa1528c31e7e9e08e1b4fdcdd21294c093bd68808223bcd9cd1346aad7e287d462cbb6674d480176a0caf81404190c0c6" },
                { "es-CL", "6c02245262abf756ca240ec32a3449e4745a20b13e3f15ab29bdcf689eef453d9bb06cb401ea7e91acdcc5e272d13391e736bf5cda8234df402f6ea5ef023c6f" },
                { "es-ES", "06182478b75a1616a3d7d00e406e6c6ce23fc97aaba18c93ae553466343ab4ee805ca8b3ebb0e1d14149fd0479ba06b6a90ae24455e7b29127483cc7905b8516" },
                { "es-MX", "b250bfdda5cb56613138a09951bfcc1918fcf300773cfcd82edb21fe5543c4536a96e48aec73165f607b52efc32e119cd11e1091c373d850f514937ae9fa61aa" },
                { "et", "505ab73a1b97f2e1911eaa2a63b83ee6f24758585b2892b1406f25464436e91b4d9040c5b745834b105337a04a9dccadfbca3e9ff1a36ab213537c624e286071" },
                { "eu", "cb4d5011b0cdd596c50003903dfe5d3d25d26618869f2680f2ca773002dc5dc2ba1bb1737a09c009b0ae71dcb885a557240b9ea3cf163788dd6d098902ff533b" },
                { "fa", "12e931ea0c47404045209e256d466aa5b677fce41125f6e17cb7bd6fd945c39393775d07e704dfdfaded5d2342075389bec3e0c25138f798cd1e383ea71d412a" },
                { "ff", "8aa52e2638414e5fc2a85902ccc18d29456f4cade9f0046fd39af41fc82a949de56d303315236c3157b72807814b69d19ae2c0860eed9de482859ae284b705c4" },
                { "fi", "3fcbc886b14002083b737f8f7d16d60d591423ba587984df569a49467d1273e3d0e36adbfd4afde886ebf6af2da77653cdf5d9e8b67cd86056e286d8469d4fb6" },
                { "fr", "23616a4e16d70562d0eadfdd315ff88a6b60678a6912b33a50a74d587bd1be85b4d25031920f05bed8435d0723358e22c0db36623d2e1ff1386e4d8cc0088642" },
                { "fur", "4e4ef1289d825d2cfe7c4183d3446589dd2b22c895bc1732e2c16dba94b990948a6c2bc234d5c20a02ac26e9431bd2a71b683e0fabab0b3479378d70765dfd11" },
                { "fy-NL", "7fb60c8fdbaa87f7b504e5efe30ea47472361b6bcedaf44f637d3c23c736929253eb9542bdb7ba0d52db3903c993c626de55100a9abd666df5ea3f693d8a84fe" },
                { "ga-IE", "82c9ef73face5f111f5d266dade18860543534a2e06ef2ed4be164a6a44d61834f8256dd9baa4be858b263785ce4bf597ac7d641aa62a551d262a811dc513b89" },
                { "gd", "544fda7ef4afcbcc8aadb7e58234a0a6b67075ec78e84505a17018a9b500ff5ee365b0cea0917c8788c36c658e5b8b5d6333b40e8058e516589fe6dcc343b82d" },
                { "gl", "2fe8b589cc2b98961faa6527899bdc2a21782de69c7c76cb61023f7b63e1a8055287cf62bb57dcc5b7193bda980b53778b4e6a78eb0c007e5f63cb525bd9b448" },
                { "gn", "357de16a83e0c8a74db1848629d8dee42ce692f2c6a2673bb06138847cd0fd2f6f008d8c9e57e8f21a66dbf2898cafedf80a9af6506221f8419c6b34f9bff322" },
                { "gu-IN", "b03ce935c6fa5f47a6f4fb030c8db4d4cf06cb71f31ae354879b98ba63ad429d59b481dc27fd5e4faebbfc63b4e219b659cca8dde9446961351764bd80586406" },
                { "he", "eca9207478221c078c3c7232c5f8cbe9f9809bfbd424bd6364968099720b5785e41018be6bcf84bb2ec9bb8dc6dcfff5641896a0e1fffd586098d58c7c8c566b" },
                { "hi-IN", "afa694ccf8c7b00b180022697791b38008608451a9196b9535b9098e6be4a014c8f16e15c5d3af17829920c0b21925c7d7bdbf93d02b78faca52e99a0651700c" },
                { "hr", "86debe0d0da97bd5fd7afa0576bde1804ae8da92ac5e1e65992faa5192047317da0392a0070adc6848eb779f4a719ff774a4710ce883dd989e94ede075603c25" },
                { "hsb", "8cf2d685d020f623d183031f5770c53f90a1643e283baf13848dbdf1d7538c2254993deca36bc13829a24c78f13f9e756d8a589700f251350ed9757485ae7d08" },
                { "hu", "33d4062d9c65f25a56f04265463ef0cf8e0d1a02d6a8c87ea74d62ba88d04d30d41ef9c0d97d5d3c7daf3a6c62a3bf1831aa802a29685ef06e5f46640bc35b80" },
                { "hy-AM", "56a6339ba72d046be893c732020209ce85fba4f5156708c1168a37f952444ea81a39da8c11249117dc33cfcc3d7109354ed3b875d0583e864b4e14ca88ccc644" },
                { "ia", "ad1481877989c4600975313a6c25febc77714deb6c6ce6fb3b45b284bd933f01a4f5c61515f85a5b79ced0b764a478041426c47c94dd6cc8b0044229e55c3c71" },
                { "id", "693788d7f18369ee99406906421b952d205322ce35f7c380c5ac8c2a472eda2471d06a767002d2469d75c59aa55f14abd380e8306e5ba6052b67a06f6a46f852" },
                { "is", "3fba2b0c93564e0ba32fe6011f9f1b8aa4cd0dab9364ee0e821e329c881a04dc96694eed1643bfe387cc63d8f9918b396fa99d9fe0d991494ca6f87603eeecda" },
                { "it", "87d1fc2ec7f1fc5b62bc1c4b632c5c7e9c0da2d49a89517fc1f597f834f3d95adcc1bc788d8df744f823f24b11d5edebb93e93601cdd589cf6856b0e5239194b" },
                { "ja", "0329cf2ab5471b4e32dd3c2a3f5916596dca841e03d183f06ce4b869785728f7914dece921162a9395fecf0c0f41d5a94840eb724531d9fcf6c37a99190cd88c" },
                { "ka", "4f0831d1b6a3fe398108e4226033935e231d39294fae50f10174dda32ef898ebeafc0bc1032b9a5ad509af650a3a0950496dd6b1efd87da9ae245ef4a2886217" },
                { "kab", "9ba01f7bc28ecf953a9786ba3e2b72eaaebddeb030b675e7b7e1a0896f9daacb52c9b240024b6011fa6641cc171c3536826c5ede4546aecd5ab2312833b1df45" },
                { "kk", "92f50d715e5f7d11b7ca8d8ea19391e5b8ef8b5bcdef972b5d7fdf5c5a88a67cb51019dc46cbac3a101e84bd2cb55dcc48344b9344132da5d6d1debf898e95dc" },
                { "km", "ae5c40b12699b6c8dd9345b3e4e7c84aa63e8d43cd15d87eef49a50718b7c16c0bac4c981cdc7a478af1d7637cfc9db6aafe0ec16ab084742a4e21e3b2847641" },
                { "kn", "53bccc044950f4a4df2aff49c71902449ea5147ab7d58fe14d1a905377db3927db74f9280ebba5e61631b0e647dddfe24d5987ee13bafd252f142552e1011284" },
                { "ko", "7f49701e390f10d069c8cd2cf514ae27941b49b71bf5da51b5f83dde445d97932da226098f3b8a82b6c8116032677d4e1d8f6b76d8301287d7392d81a22b5a55" },
                { "lij", "247d1b18b062c3cdd94987368164794cc97d0a6d8359667ab012008ae148bb35f14b5e8933dca1aee53ea3fa6d92724d4e7fcb5147ba29b9c83fcc7b1c4c9975" },
                { "lt", "5855e8577ef0c537268259702b70776660d1913738b3692555b69039e448a71b3c5beb9b032c4e2fb38c7f770a01683e585e8eb9feac8ec20aaf6eda4aef6577" },
                { "lv", "97227af1f11712107e3b2ad4252a778a698316da59d5325b718e3ec379a2705d19e45247000d936f4085fb19f536fb86a2010a1c8b95690290c624229e972c85" },
                { "mk", "8ad0b9b63ac8d1d35529b620e0818846becde6a67bf469561587d12f60b751accb8a6c9052b99d0b23ef1a4bccd47ce849c9b22717cc55305c80278274bf8692" },
                { "mr", "4ffea0e4dea936c6e900aefcbb3618a695f087b7af0172c8bae11bcc00276c090e3328d69dc11f3da867f8c6b2158012af19f74f8a015d271609e8860b28af56" },
                { "ms", "bbb8a34b501ae7d25d7253d7a85fc58cb64121de2ec88f3b3d176739f25ce828baac428e9eaeba2b5946384b1f4e87f560a970c91f4dc88dbf92bc8962711d12" },
                { "my", "5cb0309f72c1a39d4808efed25a4f2dc0bfae67eaae957f15047a9c25488d9b3ff0f734f1537254e6b1b2d719dda3993d70f76d16fe115e0591964acdf2e5b5e" },
                { "nb-NO", "1c30c3709b7d4d3c0d388273489d18578679e8f05a4044f4601935cc36d4de71725b54033d031b72279fe5fe0727e459687ca666213c29e8505df95a4705b886" },
                { "ne-NP", "c082e6f5850fabca0676b21bfa24ef5733656f9660b5f1f094694d47fb7dc08a225304c9b68d16eb2a42da18e57bad7c118bdf3a50aec2074d2bf3a9d48d333b" },
                { "nl", "1a46ed0055af227b7e9c8452704608e0d07e6bdc3f588d0e833c74cb84052e549023c423032ff65a019449943269b1f7439b111a0e1e032271fea18bbaf3c8bd" },
                { "nn-NO", "01939bdaebfa8faadce607d085d24d1e85f5324c137ba397462bb6998a125caeb93e99626a723617975486b21200bef61cec589b5e0310f6f5983737c97ee094" },
                { "oc", "d60e3e666fd884012989751980befc23036717d0cc2bd6e76189e8500bc9a6925227ca741c59ea131e21b5f495d1ab5b3055082918fb573363571bd0e614e3a3" },
                { "pa-IN", "60690c62674d233b182be16716e4c011d05d9d7f374a45624fe311de95c18bc4bc8f7ff30873ba733b7a86b3d5d3db407796372d1701ef8a492de1f77b9eb176" },
                { "pl", "07c8e9f81c1b84d759ffbbabd7fb01911ed9a863da0511f6892904e9ef41f54dd1b151240bd5394be8ea1dd8e0c40c5677fcfb9d07b93d76ca00aba6da8df563" },
                { "pt-BR", "35c1654340bbe535150b6c3e6c363eebf38dd5d6b632b0c07903a0b7c2d9519f83eb96371d60d9d690724fb8a8a372cc049040bd6d1ac83ac588923542ac4c04" },
                { "pt-PT", "9dc28a1a5266dc77b1b90f1dfb7d4b14dfc5441b360ff6ab2d2080c251ceac8a2e51b010dca5da59499ec3c06937de63847074ef829b5a98ef4ec266c51f669e" },
                { "rm", "642106238be8eef3ec690fe4c156122d937125bbc894401690fadb6d695ea641dc5bc28540676eae823d6ea3cd9ac8add0755051f48ecd546929a28db4f06547" },
                { "ro", "c402935ce8fc50deef6899795ff213b00de140ff2dfc0b880f5fe15ae0c20cf40710d4bec4f2ae6506b13d596b24f60703fb2c68eb605d7f3e3ebfeb073f4410" },
                { "ru", "de1e22831429cc02653fdec0a0d25a1a7e6103937eb260c46db91f48a2b784ed1c7c16f985cb070f6c42772f1710f3fadb940d81cd407ec66fcd774b81bbac89" },
                { "sat", "8afacedc8efd22dd4ba205bfa4c651c456186f9941dc189e61ef886a44b9dc04de2b95ba8099f2e9f7afe9973d782b96b93640343efc4f274d08fb93827bf9ce" },
                { "sc", "5b22d07530f8db2c2eb452da653912605c904372e983a699aa2393fedb4dfe86c84cdcc815f40ab044d5dc77a6bbfcb41bd1fbfc382d928f8da37ae78d411b18" },
                { "sco", "3fa98dd9b63c001776c71ab489da6ebe1fe583f30492768e2cc0738f82ebd7496f9a170a0c1bc800171ebe08c87e44cc44db4e4faa85cb9db3b1c1bd4ff2c5f4" },
                { "si", "4cbbb185c5b5cb2297c2fb2bc3cca907d2c02bff86ef43c490e848762ca1ab3d6d427d709792c1aa55550babe3be0616eb02aacbda3278c174e87dc84aeccb8d" },
                { "sk", "7d7b5ecfcf325315b7bcf4ba9f4aaf06cdfc91b0f310af08c97faeced8f89fa04277f55cd2264dbcc717c7e09042f3b807e6e913d4b72825afc714ddb7a2a23e" },
                { "skr", "518bfb41c48f7de7eb2cfb000be337c9a7d9ed2a363a628050667c2450a7640244259a01b01cc62e7e321eae29f6926e4a052e3bd1ec9c9a7015f8a7c9d89f3f" },
                { "sl", "bef38dfdc056fdd29d3a65270919058f1852d89d1a7700c83a17fb5f90bf20bbcd368a4252f08357e1e95f09bc1a5a5804344dc3274a56f62bd5f72f5c9563dd" },
                { "son", "2fb745c5f217d4b4ee1e8016e4e2cbc6a64c6c60f8a52dd1816d15a44ef36820b840cfaeb8ea5ea5adbf3170ac5fd99bde47986293e72b318371f0693f5b2adb" },
                { "sq", "2844abb5611294a00d8d6519ef89ee1c4f656fbf8bb555f313c1cddb653b3ba2346dc9b4e34a7c7cbf554269aba5891bb468d5227aa1fe7cef9a1ccfe2a2d364" },
                { "sr", "047470cd74e1d403ee392587f970f146e5d10a12d3a75e66cfe138c3953b7582983ce061ef694d5ff467b5af1323ca19c619934b455011f3b5ee0f6e1aedda75" },
                { "sv-SE", "15fdcb3a8f27c90141ff30fdecf69dfd42ccf449854e672ba3938555b9b7229bca83be8b461e92e570b8cb66121ef7d0cee03a308b3ee8c671e40c4a767177e3" },
                { "szl", "0f95d1793605aca5e1e16dbcd7a0121efbb855b3ab7e3166f11d5aa246a2c146f043e219e62710bf8df30253c80612782a647567db6dea406640885ab0de46aa" },
                { "ta", "21c58689e96dd74f7d9920fa40fcdb609d798a3cb37e75be6584e75f1a4fe56cc4e7adcd0d32f89407c186ac0b6f5a305e894cb96f67220342836a8303a8e872" },
                { "te", "daa778127f3c171539d59b11172ce26a9e277426ec0c54200db5ee756d13b3340bba0f7a33820feb0b41f4658d7dd08060c0d0a7b0753128182fc2c7f278c0d0" },
                { "tg", "f3a6eef094ba13cbf11f28497044306576701e097a701073f1c3de6cb88b4ea770823dcc52b7f2526ff65865e2dbb273cc41d13c334adcb55b175984cb6be9eb" },
                { "th", "d490abfb1518652c83692ac081b6a4e032935a9a5e21de309ed8013dda8ad17c32666b4be8e05cacfe68cae6d484bec354cc4d626f39537b38e52292fb333cd3" },
                { "tl", "d40db117b16810cf0afecc7380946f657de0272eb2b87cf736d5936d1cc6c19da4a517e439480d4a90d686234dfa730cfa6d6bae94cfe6d7201805ecb03846b4" },
                { "tr", "15eb295c3cc766577b28a0b4601e6b4c37b4fbe4c97cb290a02025b6e11b5e753f0ccd721a41087f4b45cca5710beb08159ca819123c0366a0eb7ff41dd7381c" },
                { "trs", "24cfc9fb2a8686d39622ad04c7c559d959c709925121ad718446b2d2f12216739a434bcafb0479cc58dd21888574a9391af6e8002ba3c687660613ee489d5707" },
                { "uk", "203d3cf284a28869e25a8ad86a3619ed8c4237bbc911bcfe031b01cb510d17fdbf8b535cb262a6346d942bfe17b8b888533474481cc340f7b014c5e1ae0fb0f7" },
                { "ur", "654c71a8ed76f4ecd567e0c6de0818f531fa110a0c66b0053ae76312460c92e095f56eef2e8d1b083fe403dedb38f056ee5fe165f0f79112546fb71218f3060b" },
                { "uz", "062b48c960e8776c7faf4bd16f3f47abc8c15d27033de5fa9153bc8969d665cc146aff3c72b0ae001b80835a20a1b337e9bff4230a754cf5fe62024100b10f9a" },
                { "vi", "b7e6aad803c6cb5639dd3a85ec5ddcb1c5cbb900ef8414ab604da53f16baf6f1ec4eae3d018f63a785af07711a1f77cb6e565cff7e81466b6fc17f1cde9979a8" },
                { "xh", "9ffb06cfb715eab7923bf476af57b2cbf748413906efd998f227c3b333e36fe30995c3518ebebf3a20f3c975ee7bdfbb1001870ab40a7da2d61680869e47f502" },
                { "zh-CN", "35890ddc74b23c09546d8b9f29343ea8b037487187d978e2e4608e01acc834b2cad1acffa001c79d14a634952269478fbc906a34e0fd8e6e98965c23e0fd9a35" },
                { "zh-TW", "d12286a720f86084ed524f08c93c0ef505e7b44bb532b211f2863858815e05001ad52df573db13e189611741e897c18022319cd91d71979fc6660424b786f3ef" }
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
            const string knownVersion = "143.0.3";
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
