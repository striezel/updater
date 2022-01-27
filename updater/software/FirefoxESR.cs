/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2019, 2020, 2021, 2022  Dirk Stolle

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
        private static readonly DateTime certificateExpiration = new DateTime(2024, 6, 19, 23, 59, 59, DateTimeKind.Utc);


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
                throw new ArgumentNullException("langCode", "The language code must not be null, empty or whitespace!");
            }
            languageCode = langCode.Trim();
            var d32 = knownChecksums32Bit();
            var d64 = knownChecksums64Bit();
            if (!d32.ContainsKey(languageCode) || !d64.ContainsKey(languageCode))
            {
                logger.Error("The string '" + langCode + "' does not represent a valid language code!");
                throw new ArgumentOutOfRangeException("langCode", "The string '" + langCode + "' does not represent a valid language code!");
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
            // https://ftp.mozilla.org/pub/firefox/releases/91.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "f00ffb02e303646672960f5ed754add25628f0b8d9fbcfe20666c3ca147f5622ffc429e4df47201a630a28b6df0c2e52c0ece4e0b00f830c965c2a12285eb547" },
                { "af", "8564284a2e70df9a9632da08d153ea729fe711ef2a63ea7559193b342f712006594d7d21e4eed876f291ef937924111e3bc581ae929e324b76b737fe70700dd5" },
                { "an", "6ed44b5fc03b4136a9b15aa333a7c3025bfa64ffa8b83ab4f5dbc93e5294cc1253b5e5bef2316943260aa7b1a5feaffb34f100e2dc163c9619a632c9173c57be" },
                { "ar", "c07c8f013d13d77fcf02d0b2ac101d19292fff85caa5cc4a0f386ddfd115aca3f52f7aee135858d9c09046cc827355d40ca355f364a27ee9a3e10dc55821db61" },
                { "ast", "fa327d6883c6ba960ca07d9f668fc217a9727290d200e379c9d2974d1fce321ade7b212a5a726bafcd3107d27d9fcf27e71fcf4436d2903bcb6f676cda2a9c0c" },
                { "az", "33fb5e1eeb5f2d8dbbe1dbc5696bd5b0606675e9c3cf54c7cd2636b965c0ea7bb136d327fba7194c7c0e4015be1c8e012c4319fd13e367d465b5a7fa2d9ab10f" },
                { "be", "5e717e2d3096439d42bdca4ef0cb294db4355f4e35fdf1f7d65c697695ffa1de8065452dd0c8d16ded58c062deaf1857b14b834ad186d6a7f34aa4b0a68b23eb" },
                { "bg", "0514987e8bc7f5ccf0ba4f84f1802562d39474bdc422f283982a046b02d30270cd91fa1d7902edbfee69fa9be88bf9c4664b990aaba66891cb1869089f3a846e" },
                { "bn", "94938b4d07984deface5e44dcbb0291819ce5a4bc5470205c13a6dc6e690388003e65978ace878d62777ff08091724ef9c8fada288ae1b00c0f34ac98f14a848" },
                { "br", "07e5f682a6ffe4bf3620eaf7dbd7c61a83374f814868725fc667960f5fb8cd90080bf515cc7c43785b4a2f61b5cc7023556184aeb508cfb7edb9fb86c8ff6339" },
                { "bs", "1104d2bef0d9ff777b3d0b9c2534bf434ae98988d7b9ac9032f6924b5cdf9bba61155929c30816bf0bb2d68206c6f6c331dce06f91467531ecc1121eeac9e006" },
                { "ca", "5f69368029c3abe5459f1b915855a3b7a984a80b4ae4d1d267e8ebfa9a7f9111708bf06d1ba0e92a2576708f1ebfe011783b581f635ab1b030fea0bab52bea1b" },
                { "cak", "6d536ddd3e90c3b2637196b145b2e70686bafe11e6eeb8a28594c6b339e928dfcdf47c7e5ea49a94f3d9886524c0dd7d1254e17df60aa96b982cbff85b72168e" },
                { "cs", "d081dccc2589da290361557d852283cb50d87a74b7f1ac43273fa68337188e44aba0cf29af30361b1b227f877c43f05c06eae5edb473cd9ad96b079e39f9e807" },
                { "cy", "afe09bfb9926027b0b4c812eb9eb2ecfd3cef0d25834d8ca179c5a99cbd1b28c3b872a9aebf0c228e177a09b93799017bdca12d1a1fe089d3a8d3337e1872caa" },
                { "da", "6636d0905cc0fbfd1b2acab7fcac2c452cba48f40e781361bede39115de9b1f6b68e486a6a71f790c6102c975f43a5799a5492651e80c4ce52ad432f6cc4bd22" },
                { "de", "2d4981156cdc5a53fd266497e4a3ab9620c15a1190eea118ff7612b98437f009ac4cf96a5c4e5621b4ca349c665655e20d3cb75370e9de51664242be649b6fe6" },
                { "dsb", "0af0583668267f4c55112fe5cb2aa4a6061aa69b98af1f1fd2870254c9c319d42446015483928db3c37b58b0924ed011ac6849a87faf31e88b2bf2dfae083f2c" },
                { "el", "878995cec4e562d8bc291c6f33906b0540f71a13f6f91fa6867d1e2632ff0f1b843d9cabfc5260bbd496afc96897f62a7fa9ea1ccf3ebe48129e98184173a0ca" },
                { "en-CA", "dbea635c9e50ca83dc2df7fef18fdaca9bde4b2f8b34c2f9cab4ac39ab0cfcefbeca655dce237ce5a9f9381094b101e4ad172bdb9ce190b96c0d7af6401f9ca9" },
                { "en-GB", "1218c9b9821495d3a060808e8e0bcb0ee19ed2a445fcd14a7d8adfed68161a5330e4431881d6a9a39beeacc1b32c35027a4c72fc22f54be384cab46d45109aa3" },
                { "en-US", "eff287d239d4b7ace847e3f9a7de2bff2ac0312c243d373e01a163d8d62348c5b3ebf67aafe6beef603d3544782a64053acecaec1f4b7098d52da34ebb99d8ba" },
                { "eo", "4c697dc9f171aec352ae4d4c527fcf7e3b47d6c9b8c63faf7066e3792f4d7596852adaa4250923935d6a2314f5f96802cdcef1a1466ab35474d4b9221c5c82bc" },
                { "es-AR", "6c521063ff99dee627a7013384e48c3f1ca911a5b799911ebd25502e2f790da37fe935f4adf30aa0243740ad6c3c0840d44052fdc5dfe750744c5514e42c146c" },
                { "es-CL", "7364b07eeaf5ce20af1df5b49260eb58ffe33ec4dddbebd1b483382af978569a7d2bc0468f2de98db9e3bd5f66a6d56b050c582aad471e53ea6c60b1cec9da56" },
                { "es-ES", "03734871f6d19de107130e7810103d4f06ffccf8f97fee0b5c597144d1f67e3bcdc124ff4b74922f56f123baf99000c8730212b5ef49a891f9b406102fc995ac" },
                { "es-MX", "470efe37fbeb0b4fdd54ba30cb94dcd253573e0998d9a2532017d0b0dd1bfb1611eb8c909f898919d98fa89c826cb78f2f30d38858627dd3854529fa554027a5" },
                { "et", "9c2220be8e6b902abfafec45c1c1f7dd95e15445b8fbce9f788f9edb21a803998909baa5200287beab7fb92bcec70ba6ea22f66ea18efbe4dedf5bb5685e9559" },
                { "eu", "c474045a447961336f05f7172807722350d32b823d86ab2e1455effb71a157e29ad621f0788061d7171d0f3f2e72e7f6ac7799461e9c44e79701c99c0e7e897c" },
                { "fa", "eb663e5ef87a22069ed3f6261326c0747d81028a8f37eaed8a7d3b4fd067670798993bc7a14ff1550805608be8ec30db67703dc5ef69ee54cf6c7b1f297f09ff" },
                { "ff", "1d8cde52e8464fec045d240939080224dc0b42fbfe8e23399e2288262fa173e50dee9b26d11a18aafc9bc4d76f5795bcbacf6f069dfd24c6b1be2e2ed18abd0c" },
                { "fi", "895a4b6e5607a0263a2a6e4adb80d164f152ece6e0b4d291be2de2f208e4d6345bc8ec75c1dc5b56170a6b56650292bd8952e011bccbb07ee4d56dd84fec1333" },
                { "fr", "5c3c92d045e55451b0bb688debfe8d738242af468359ca854d0083d5ad304b016783adbb83cd8a151d96abd2729f93240279b62618a808f4c1807a89ea8d90b6" },
                { "fy-NL", "71f43c64234b324ab383ad040f776fb8966ade2dc83e6f6618b97a0652e6dc177fcea8eb6c0d7e4241222e9291bde96ff90aaed05b3661ffc8a42833b2bb36d4" },
                { "ga-IE", "59d673984f31c83646bfdd809ee7657e349bf2940142f42b1b325ea20c5a7947ad6b5cde085eadaf2566d10951466fca16878704bf5c88bc41fb2a824d35da65" },
                { "gd", "90de24565a49534500a11afa455924a9ed4ad71630f2dac9489d95bbe2f52c5fab32971564443197a47e10ce1fcdb41c360e9b415fd90d657e1d18a858db9ae0" },
                { "gl", "57fc1116b4dedf00eb2a3ab2e093ed6b1656c8f196b51291cb952c94c4f1a376a9a7dbd1bc2373a69cc8cc38338d60dc57e6452838a7348fc97cc8e8538e6911" },
                { "gn", "53209d7e8654723f2a1c03f31c60b4f0f44b580f727bf3f80ead799dca16bb0ed44866007eade53c67ddd983e837367028966d0b12d58581e8773b1ce236474f" },
                { "gu-IN", "d8a20bf232a2450365f60e3c6fbe0b545170793f167113218115f4fdd49211d59afc57d296076e2547e375484e3c4387fb779d8d362354a17fc1a6ba474c39c1" },
                { "he", "c5558288ce6974be91679d945fd6b31e10045b18aa8441562592966066ca0f58f0e1f97af618e5492dc48cf28d0e895c3ed9fae74a1ded1874939f7fff0325e7" },
                { "hi-IN", "df55af12dd0db770dda07d8cca4f498c2eaa5250686b56ccc99b17e482942e70c5615cc742bf20a4c4f63896ff0061a21d19ff6f283a942bb8310b860889bf38" },
                { "hr", "d5ff7f96619dfeb48372d2e3a1f50f5fff265559bc9ea97cbbc1e57057a39538a4b742f793848fc593d356f7bd45f5ed23057a5498d46e5640058454020fd148" },
                { "hsb", "9af572adb410bcc2e91346ff6f674d2d39f1147c0468638828abc2c4a9b93529f1b087b6d64d5815ee4e46ae16ff20a492a1de4090a0d3f443b32df75f79a28a" },
                { "hu", "81bcf8e53ed8c079060c2e9fed98f3067dbb0ad0cfe2fdcac8ea26d1b15ed8dfc560a2bfd925eb5c42e1d5a8eb2f58c0d7133203516365499be663c541a2f0b6" },
                { "hy-AM", "4519e17a9c8a9372d4d204ffd02fc46930155ce348e74099a4350609f684cb7ae7f10d18a80eb6506ec9267d58352853f40af18b91238b709311d21d417e492b" },
                { "ia", "34f88f404d375c7372de1799bb9a2783c1eeafa14b59c6ef17e2cef6d5310edf7722afac2823cabee8e2749f05f00cee80d6a17215c54ee79ca40f06e35f51d7" },
                { "id", "0088ad1768ab57fcd90bfeb7ae599f77b0ca390a65f97254f13f38cf6b612abe03ce8a5ce028512ab14e008d6c1671dbb5fe99804a545b7d836ffa71dde3b032" },
                { "is", "c87a5a5f8d05d241a71aaf0eba551666d628c9ed56d3584b8506aa356e5c13da9ae14773f7f860c27ed929180f7bf65ad27ceba7940f134e351175be4e878492" },
                { "it", "d4a4ce05fd4eb7f05a07810a76de91dcddab23bcaaec53d46242b5f64975264c90cc47dc9a37bdca022fe9db3cf2b1b00383ead6625b304cf12a376c0749e25e" },
                { "ja", "a301856f0dfa8c57475a9f10b494517255d23774c306702956415d8a327720612a0ffba4afa8ec0131b216d2973fda397a8c45c4c03f83e4299deeafb0d14cb6" },
                { "ka", "8f0afa521fae27ce184eba8819a1e50463b279458989dd375f223f8531a405ae927abdb682040d27ac20e62a6ad18e3b386b4cfdc360e9f5ff0e84ccb8141413" },
                { "kab", "6e3936e159c379e208acbf23efb552d7a6085576e03e275c082d9858a1972708d3fd4cff77d7f570ce4302cf46327e19648747a8d88961b91316d7b445cc19ac" },
                { "kk", "0e01d1bdcb4afd1e192fb238e1685ea665f47e13827c183f5ca02e325f6c554ce98e8e2a2f8e03cdd2209ee4693c8b8c017e5f04f607e4d4df2c4de7a9dc7c6c" },
                { "km", "5a84a6f41ed21336804524c4378b7ec7bb64d86d990b36e31abef90c75cffb3a230448a8ffd19296bd76e57e9fd57bef3fc3500b1046ce312152ac34b44e2057" },
                { "kn", "18e6920926d3fd2e905981b06055dece33c9e93d3f77f487937d1c8f0ef6d167d46c9d9e4aecd48fb178f13d90aaecd8809de50882036a86fc53fad0fe1ff4ae" },
                { "ko", "5208de0007572429b17fbc8254f26a608cfff28b0a7a53af518a30ca2f8a4abc70f3d7a38239841d378ce8c09110ea9788a4fe8ed5907831eaca5bce340e5019" },
                { "lij", "cad69718e0ba1949dad20e64ad9997620e96385adcb1379309508a2a60549358ac33fc9fe07227959abd7d810fd6893d0ca50751ddf3e3eaecbb3b55b864c56e" },
                { "lt", "fc34a242e859995bc11bd9fce852a6e86d6f0cf1d339a45e54cb47b250d329f3f8a4841af3bec279cf29d95fe6035bc3f47df4b6f7adaff5ce8ab7c080fabd85" },
                { "lv", "e5ad1cc75bd4607f0695e18e3b9d07038baaf48e610e118005c9decd13a89f603499ca659358a4b2b150d40157e0c8531ae693cb955b0bb13ec9a3a650accb68" },
                { "mk", "570261e3bb450194621f11c1b667aea06afde176407857a672194d911e8ac91f7d7632f8589f82281e2542275eb9af3d868a5f04b38df86c63e6c3a943446791" },
                { "mr", "5922cc1d8c9fe361bcf801216eee98627ce953851fcf07ffa3d21cb635d275db0f4b7d81a77edb6647f4e655d332f87c28201058b5ac0d70d3a1f427347b74a1" },
                { "ms", "fbfd5bb3e9b121d46e8098c8594315a42a4d1b02e42945981246d104aaf3ecde6586b25245e3ef4ffe4143fae1b256cf9635a573482d92a8f3f0e64f7fe56adc" },
                { "my", "4a9c38f27848f3eb6949af5f17cd2b7236f37465df66069b13a89cf9a5e7065296b395835039548a176c4fea64d6ded6c445b8e0f88612f1dcd4d8fbdc3f224f" },
                { "nb-NO", "7f03011893d8cc46dc0b4d648ac8fad9ec9d990714f5a12ea63003ec13501197a49406b8530a92e08294b76f477f5ed65d09aaff81df6dc626dbd381c13eddd5" },
                { "ne-NP", "6c28d112945754e8b5da11ef3259c6de21bf4b1217b94f1d1b462278fb5159c08d04b81f7728481c8fcc828c0a22bc444ef8a9132d3c0eebdedf4726a840ec1e" },
                { "nl", "dd6e089f8aa2070591482278d02ec5916343ac2ce62f1a9fc5cf8d9b0cf213d19283d657544fccc6f3dada73e5717ef22b2fa0cf2380111a768e3da67a9f6ec6" },
                { "nn-NO", "80d28414be0ff2a4aeead79aba27ff35aecedb2f497dbef1b6e6b798432bc094b516c68254916d2302371bd1893aef177ff60db9b8e8a7c57171f6f72fbb0752" },
                { "oc", "d3f447acbcd041b4b2d8663b28fb48a36acbe32e5cc18a13ec58a4ac3659f62028e25ba83d32024c22a6d4ecf80c1d44bb0ad51a00fde459cb36c686d6897cae" },
                { "pa-IN", "92be09c161319463886176aff154c566c138f5047dbd6b8f2c83e73c091a1e3651367d46ff34ad0b1c564c52c547bf15df5783c997d88967faca6e138cc4fb37" },
                { "pl", "ff83197d55f6ab1a47f2a510b8cc6307660f8ca1044938e80a5f8de5cee45f7cb13e579db6b631cf93bb66e2a9ece4da6cd99cb44e391468e404c224d1baf260" },
                { "pt-BR", "5829abe2e535275fe37d9dd6079ec282a4db0ccca9da51abf0286818b98c70ed7bbe9d32d434bcae5428d683f1e712887a201ccbc8195d1f2760f9bf4abb6c8f" },
                { "pt-PT", "de0319ba277baf08c57c11300fd7a59783a92bd5b7dc3963215af63987767ec7fb6963cb8a5d7cb16998f715b268b681e7fc8307207b365451bbfbe4750f26e7" },
                { "rm", "ff14557ee5433bf6c7a69ac9f31e78902bdb3d06b6140fed35be5078245f760dbae07a2de3a591efe473aa85914355e7788f05d715c5949842a2ddab5d589a53" },
                { "ro", "df849a6fb1707b648adbe8f25a7137888f15770458f4c1106499632d0c71e471c8cd401fca4e2abc4ac9d08d73e322900873be93fbed362b08eed48c8427e0e6" },
                { "ru", "0b0312e65a277e0b2db32b695dbfe662a8a4a551d7fc6ba7041dd59fbd9288dbb280b449263452d3bd7906a9fe31b32b16ded10b84f6d2e5fc42533d70496a6f" },
                { "sco", "0921914bb37bbdf6f93da54074e9cedd08cce728cbfd2f17a3e3561ef2ef36c36089fe56911d41c39cc2c863eb6ae59ead56ecba0bdf411076f1e524a1093b95" },
                { "si", "cc598c7b17c9ea05541f91a2627869936b2e388f36862b2e07d6c69694c314c7e8211056f4678c27af37603a4fc39840f9f6d318fe24f7fc5b3e430a7e5310bf" },
                { "sk", "8444d80ae768700014cb672cca91809ddd8faa3d5b8d2564d2c2ec70f92ada88628b6e618b89fd021cfecf3c276a75bf0a76e3b2d34364d1393fa94881b18089" },
                { "sl", "128d85e22decc5ae73506d0650901398351b4ade55b4b7f145e7bfd8b2e08100550c9068ecf0721af7ac81e3da0b127630afb38c5c53a152e79fed9f5b0f8f1f" },
                { "son", "cbf89cc76ac723ebbbdde70c7f2107d5014cd022bde1273c60f907a1c5ae52ec611c076c9af650116af95e108eb2662236c4eb3d9767c97a25d2b5491f855605" },
                { "sq", "ae35c9c3023111328a5c5aa255b3d171a7ba12bd1b4335c8bc4a67092a85431579bc1762351e7a2a95547f463a484517706c4f76fcb4a626f539c678f250e975" },
                { "sr", "b10bf62664f01105cb4bc624dedeaa95f9ace9f72eeb230b0e987631f23dfdd5de776363d9cf2063c41f66e38acf8aef95b5592ca0dbf19e22dd53fbad0caa6a" },
                { "sv-SE", "ff28663eb0ff72eff247e1d03e0aece0603dd92f411717e4513f75597a0fe46ebee17bb59542c55ae572581bccf87595fa7ccd00034b1592108632bcdf5c91f1" },
                { "szl", "f2a5038708d473d130da3d64b90544de89459614e957f773d028d8a3e5778550a895984fdde8d65a20f6fbae7d58ae7f0c4073a881897121401a2b403c1b718b" },
                { "ta", "cde25603ae6f6509dc286fac976c0b8dc1ba16e3707fbcc4e13e294c47b42017b1fbb8442bfd4b4f118a692c9e8bacf1e12fe5a6e56179d21b6dacf500d65978" },
                { "te", "d34d1f1bfbb28a44a469a8d7dedceba2f65133e8622a2436c9df997e56f7b41e662336f240598d240dbc5274e1a047f4b4bfd77da970c8c9aff6d3d0d820b4fb" },
                { "th", "05ce9cde855cb53adbe4091e0126cd7fb0b39bd6bbb7c0645f5c1c98f8e1eaf2b11730b7dc8cc7805b19ba8606521117b32eca116ad2941ae8b4a2d0f4a6b274" },
                { "tl", "63cddee04239300b39f45fab556ef31471e464cc439d764c76eec3e7557deaa7e5227759504d960eb5a2951f4f3c17bfb40ca43369486a99687024ffdf3a3858" },
                { "tr", "fc4a4c2673c1da5b779f67cf324623b23e0fc78f155618c721088ccb663426704c0171b416d32bb17e8f97865a813620acd2cbd475781e8eae3d4481b34446b1" },
                { "trs", "4c1b9ff90c6be1161af27024323affa050307cdc3e6458f682ce7adab0674102b91fbab244fb880e53dc5ef3c83e422eed03abe391ca36774380887a9ada6ebc" },
                { "uk", "18d6df41490feed753ca45aae6b3120025cdc69f16420498aa3bd64b00d71510f20eacba73ef262d71f6f7979384653f0137cc4559aa89e922188ea3ab9347b6" },
                { "ur", "a69a64a98c94a5b3f134c278e9e90bcbff8083ea51b7995fc80553c651990c50d3f03430268cde23290aa566f2c3d6e9d0efece1cc292d3968b62712ece848ae" },
                { "uz", "2e38ae8b9b3b97062e66e8008fadfeacf1046a508b1cfcf543b63a645fe20ec8a1fb426e29a50b636fd99efe31ec6b01f1fc28e0704a86a937eeed11f37948df" },
                { "vi", "89bc80faa33188341b258f2f845f5d8af92a8fe702bf348bad9f761219dea6affe8113585065bc014f7aba565344c19bdd48e9c91719b68f3ea8048537fb908e" },
                { "xh", "fe10368b27d04484ca285056d333b73d294535ec0ee1c26ca23332a62f7f6320f1d34b519b991228c529e1e5ac9ffcf5e6c26b87fea9f280e35852816319a342" },
                { "zh-CN", "cc46ff10e32ccd70c3eb39b8eac8f19b885565ed7005dabeec881728cf8c8e03cd7831e69d8aae39e299bcccbbc8c611f48c88e47e782e4d32c4f4ca19813427" },
                { "zh-TW", "5fc7e6ed6a0377bcf6a8edd2200043b0ec922c38fa9ff267a8741bf6b1b87e88aa0a83e803ac7b2164547e44e2cbca037e3e68a1ae49c70583c07abf9aa9e11d" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/91.5.1esr/SHA512SUMS
            return new Dictionary<string, string>(97)
            {
                { "ach", "d0a0a15aa3b1da7fd2d065700c56ec100ead3b60e0b83da4a497aa400e589bf932402c9209c8fe67688ae71432e6944d1282771dcbcfd0f53c11be16c9e680ec" },
                { "af", "f32bfad0e7b01777ecee644375351f1f988dd5c06ff637e7dcc20685241732976dad3954c5b60afdb40843f9e0596725ef870c88d160c0f70699f99f4ed99158" },
                { "an", "160c37854f00e365febe0d834c893f1771ac368bf5510a3d808458167e6e92b3c48d3d688be5683c84ab4dc68c656a84e315ba496bcbdc90d19b5304a2d255a9" },
                { "ar", "bd4db6c663e39d8797f2101758eba8d96d6cd3115e7ef9166b3b071ff66d76bd9ddc1c640ce697df21b619b7246688d5c56eeb728ee41a26b9834e64e799e3d0" },
                { "ast", "f7411ff4f8b43b212e09d305a459b661ca77c193b581cd91e2dc7b8fde72779b6e6d7694722330fdc71165517b88bbea1f49220a6daf94be882fdf2d58abc7ed" },
                { "az", "67d47a560b1c0ad83e2b881b291fccc92a102abb377e5addec3bf22c548c2f23b3b8b90cef86548dbeed1c1bc4deb6537e61f071333e6933d471f36f1500b57f" },
                { "be", "de7825f590dbcd80c63b6a3e0ed464165b1ff70ee62f3dc4c6b2bb5ff872f8615ee26e74bb11c9d96e8ec2d3044cf5ca1629add7c3599d95cc46e8116eaae47f" },
                { "bg", "37769c61395c8a1773dd32f052531b94c3b22c2c2c822a7898589b2bbe239aa141652ae535576e47bf27413767b46e5a00e5eb486a46ef265e8baaed6c47d088" },
                { "bn", "25c386da8246db3d9ebd49e3da7ee1a2d06ced7c743d67597415d2acc94b32877bc8c87969bbe3e7c7840fb26d61113b102cd69b34529dd93f2f461ee5da79b4" },
                { "br", "d5bb76c86177b2c6adc8c94cb9d89b258bc95ac2a2a6db492c7abf23b0d8fdcbc4446ecac86a9b4160281d2169ccc33edfe4942b9c8cddd15665380321473393" },
                { "bs", "82910f02d16edbd595b723878e1fbd7c071c9b751684f0abe2a9be6e66cc2beb6f9cdfe97de72708713402e4d6bbba6eed4043be651bc609d09d55e467be6c15" },
                { "ca", "9b9bd1800b53a6bd115b7839ce307d20317049e22ae0522c700a3b6de063fcc561c0e143a075fdab53e9020b742083dc6df63fcb51496221f0768fc66cff9c46" },
                { "cak", "d0dcecd50960b01d8b1d7dba87625daec8c9e5cd65607ee609d550c5f8d21aebf47fc8fba7db620fc0b5ac621f21d3019ab2c785a023ab1e5953fc7846c460e4" },
                { "cs", "ba0f1372c1ad90a4a94652e7190502301ddeb477d7492644c9e846e22d5f341ad5f1100530993fbdc5f64f8263b7c38cdb4164b3ed7439fee081fae8843db324" },
                { "cy", "df2dcfa56e673f2091d30de0af0b9e0ac8df0630784e0f7662aa3cdc7966d98d750c44b98b708989817522cdac4d8f97cab26a72a5098b0c7e340d6a6eb93681" },
                { "da", "54c498ffe6511966e261ff32df489e602fc52f64ac99a65227d42915799e8b53c344eba2d818eba793607bd1489b79ff8cd1982ee3b74071ed7d8c8f2ebfe185" },
                { "de", "674e400ab21cae1588b25eb84270d5ad3e48874d6363e2ba058ff90848983998a3075e58019953dac1534b2a82ebbec2d5a8ce679defc453da82e073e2203b72" },
                { "dsb", "fcd236db7a2b5a29c6a11a58a06f7fffa994ac90af9fc62bfc27d5b45564a9569a511e84ca4810f2a3718783ae4f36b539e39a8a90a42aa66af3454090b31c65" },
                { "el", "3bd9c2c3029e316cc7245544ec5cac2f83499b20347daf2ec362cae737fa8c8e9415fcc4f4510e9eb04bd6ae19bc2fa062c1438cb1d11a472333ba77f9d808d8" },
                { "en-CA", "7c70a8ded61da58a2d681480077d1bdd19de8ceea183cb48e98a91d5f491cb1f12ccc5a6378c49189a56cddc8b4342e1b987167f0d1bf5e00a2afacb16466299" },
                { "en-GB", "a0f3e344dd67ab7fd18b35b8f8798483f094936c7879209b12b3f8a3d2321de5ffef20c9768cb62a11eddd566cb7af4f8bce7aacfd5c7bea79710c62a51d73ad" },
                { "en-US", "bfbce2b6a433ccdfa6ca395786bdf3e33cc21c4606da66e678aa3d83365d1166f80d5b74944bd3278e5905d7e8327085af52ec0f2ff388e0386ab90d0e1fd86e" },
                { "eo", "53d580b52cdd228ea4b45638102fa328a625f4013aacaf3d44e979effec4657af473e4cedcc9697843b4c99ac49eae6e1209a2fba1dcf6bce0b4eafe7f6cf78d" },
                { "es-AR", "06665fb6ab8b4021a5f484e722a4be8b1b7fc565aa94be7be4769afd467bf2eaa66f3707e9ed6ab9a501e4404d8735ce7bf17e87879bfe3ecaadc8e7e59523de" },
                { "es-CL", "0066b2ecc48ff4a924c3000918c268cab8bf2e28fadf37f6ea13a0f7a589a79676918ef04ca1433a26cb78cb7288806658f1c60a80d80e076585e6eff2a14ef3" },
                { "es-ES", "1a082ef28b376fde833ef9803713d285767726f437cdbc6acc2c5cafd784008f5a68b5a722b524335c79e5ebd6fe8f1928fb431550e7f72658038a4c73e4001f" },
                { "es-MX", "9ef9811b0d92850928075f38d711a52a0df54ecba04a58edb1c2000253d0a53d44d21029c414a0bb6ac25efced322ee11c6823249f34711f09785047a8a5f632" },
                { "et", "7ae001d45e9cd1dcefd290cb959c999aaee9709c016cb1c0dec5b810f632d25d48387bd2a63733023a4e7be857b74df10492a29a575c9eee74bedcc6a8b121e4" },
                { "eu", "cb86c703b2a23600faceda3b3ee2166a4d78ce0f6701290fffdf0fde2ccaff49c6514b32c01d78e7b328ac27ef34741bde03be424851cd2eb0a606b35c63c475" },
                { "fa", "3feb49bbbc7b9ba61325f6f09d4d0d902264af2c59acdb3d470d6d52e801511a46e03b822748d0e408683813d738f53fd93a131f826fd8aa274bc4d90d946d55" },
                { "ff", "cf2f6454a3d1074c2904981e9b29654730a70b37d6137417587224f966c02ef4c070766a46b7f0844e4bd9ba96db5799412e9e33c2a0a072d6aa444b1e9b9dec" },
                { "fi", "281ff3b969e17abea27cb29789460c1a11d34c69eb695c28be310e74422cd0faa65ef2c2f93e3b0a26bb5dff10199c7dee252572849fb7db851a63e7e89c514b" },
                { "fr", "a073866eb857e539b48c3fa906cf8385451deb1811ac483a0404e4af81f567aa57953b8487816663576939a0e466138458743ff17aeea51df05f156a89fd7682" },
                { "fy-NL", "0dd19e5b8a19725e810d3b2019db0fc40fa8a3fef55b5b24b936b236d05d12de8ac38530636d3a1f94260913cf7f847b184109ae2a05837a6bd901b20cf63ef6" },
                { "ga-IE", "4ab00e02b642750c788ee2212132c2a040433d0b4061b1f2dd09c605f1e3253b0c8c2b681b1f476e071abc483fcd07005e9c8fa4f17221a65dbd186b4a85a74e" },
                { "gd", "94adfcecceb39d759cdc425d9bf78d8abc7bb9bd99d51ec31cba286327ac7ac6ae45ca53b6c6e7d747e13244ac7bea86e06a03e995ca3c15f07d0f77ed550110" },
                { "gl", "9a45c6a16c9e1d94e825e3b9d128113022666a664d3a420549e5441fd4085d1d04cd0daf1c80e218f38544af090ca25cfd9e016293da32ee23591e6e8f4388ec" },
                { "gn", "caae6749bcd7136834653eb4b800c2c871c4526cfe46477171d964e01a4bad6f6305b42ea470d7713f098b79d23ab713a8bcc83ac2be8c82d76f97f244336e99" },
                { "gu-IN", "70e8e2072cedeafa854bbe1ec3fedb09bb7dd68e225f450d7c2ae1c60c71c3944e524a71f77e985ae0284b1a810145863a06a989b1b48feea52d64fdbd280e5b" },
                { "he", "e88161320cf5e782af19c442cbcbaf5a656555d3b832d0fb163403e636e8e4d907ec9a4d39aa38d1cf4c49d16241d74863e57a451854e7d7a48b9e2f864db269" },
                { "hi-IN", "52b4dc444922943eff02cf89219cf1e4e555953335d6e342b57305187cfca4624a5df2339f2ca9b1cba7b57bf8a25508eb611cc5dbb6f50193521b188db15173" },
                { "hr", "347135fe80c55ccc339db5585856eb9f1a5702e665b66ff824329e3ee75a0d4ab9e786cedc14bb3e769dccbc0defda17842b984f6944b419c0cbd63b46912f3b" },
                { "hsb", "b42891cac3ab23698e1d196d77a2adbb503786b8a1831e84cc967e68a619c29fb4b850c7935dc063f67fbaa59869cadd47eac623e9c889cf109657f60dc01a61" },
                { "hu", "20740b20fda99bbb0a0981d05884beffeeaad2fee4436f9fe63c27dad5e579708ca6490ab3b50158c3665d8c6519da9d20f28101e905291446ae77d0446d40ce" },
                { "hy-AM", "527e6657d1dc3b83acf7956861cd725e7abcff09e39ae5bd1a5125fb9b984e4697254276f118d01450d900e8eb414cc9c6a9ff3392d5c2e7cdfe95f3ec537728" },
                { "ia", "a1173039303b6c575c7868ae33b58466f27ca37975cdd23644b52221af6dc5ca07b3d7c144d05996cbde1243ea67fa0340072cd14a69e8f98b38b51ea40dd71e" },
                { "id", "cc5c5b7fee037b5446e639bfdef5e6d538024921922646b9f9d109e07920b21b3a6c36b1cf05626bb871c90f09f61728c8c930e6c77368ab36f055341ba760df" },
                { "is", "bf4bc2182e58dc0fc1958f94bfedc5fe5706e46318532edfe70c2983e95affd715da853dc017452cfaee1f6379bb49d456fb8f929df8111bcf7d5a5b600720f3" },
                { "it", "c9392269d51d6b1fa94620cd5ae7d14f17c510d1b0371f1d164e65d5752531c744c8b64d078d3b6066ce70677eb0a228952cce085cf63e25adc319d1898a55ff" },
                { "ja", "7cda282b4dd325836f646f38e62809bc214c1598f59f1936240e30d8797b1e7c6f8c24e8bf0610bd593a2177015862b61df4bb2ea81d99750b4fe093f5e32a1e" },
                { "ka", "d78a283faeb1d257257cd18aa132909032d678e2a780a1bfee26b35db6d04b21f5d49c263d548f3549584007706bb04073bb3104862f31e020eb1f9e5ab61975" },
                { "kab", "64bbfe3dfafb3f645489ba0225cce8f012b2caec4b9ac4b3631e239dccc29a75e786e89a5d8fe5ea98b003348d77f28296a8f9c70e852efb05e58f37e2c3a9af" },
                { "kk", "354ed61ad542e44e8a2c0585478db288720d75c99d16c28f7ea03c0110bdd592a66563a7aca53c99f34dda78b8e2d7067e1f18bfeab78a984ef3feace60416e7" },
                { "km", "bd9094cc0b53ac6e27565040573142089e3ed3f52e197776abab698a966cafb48b0f7d4f75050f8a1517f57dca028e56440ffbd2c1897a256908a9310cba314e" },
                { "kn", "b99066fc5fa9c91f5983ed9e68e5160d72d739fb229622a0085cd5b23c86896308bac28e68010bef0176777bf554d2d070aae52662da2b7229b8bf67b5a66d33" },
                { "ko", "7734ae879d0235c048aaa611d42f7a2396194d75b8cee573647221afff8a72a1231d7f40d8d2534a0425870df237579a909c6e293928fc98f30aa1ad198609ee" },
                { "lij", "ba9eb97050a60f57e4001e365bd358ec66c8c7422391ed8972db19bb6de7543dee4262903b20e0081e223c5fa92f35a5aede10827e90f630a8bf2518ff2d8ae7" },
                { "lt", "04543a9d55497c64c84c2a177617e9aee3f4101796b79d0727bed69df79c0eed4fb5be9a3da2eaf4b21da287f15cee96072dd8478fffb70da4a0cbe18f5f54b2" },
                { "lv", "cf84b6e613375c20cbd5941e0c4311844319e7d87cef7c0bf7756738ccdf758aff14bab0bd172036be71fca9353f8e855e3969d1b4b5e1cceca70fe7065dc15e" },
                { "mk", "609235d0f6c17f6b3e2c29a87ed6e2dc692234c1013dd591a3badbc4c1a0cfadbd05617b63e43907a126de1bc03781b65a491eaa461fbc97ecc74f865d4bf77a" },
                { "mr", "ad863499cb0e02fa4f96357d2586f45bdaf4c257c3a787559b38219704b5e976dee11749cc67187fcde55fb5eb2e3779b7e6ba18d1555fb9d0c67e17da9342fa" },
                { "ms", "4f5fae87f2d597aac467cc4d239fc8ba91d7929e39e704456e435967361c7dfa66f11dd306739c79ea1327ee00d3ada70cb253c3877295b1c68136dfb2eac607" },
                { "my", "defb9f2107454b0be0429bb567189fa7a2d753d0c978acc3ce251e3d9d24e7f5edc780d41dabf9c5799c95fec4cd91b999591711b87cb3a3181f3f3834c8efa2" },
                { "nb-NO", "ff1ec6fc9fc39ab0a2420fa20ddc7ce78994fd1fffc4df6594aaf0cebbe37fa43c8059c2304597e986b46868f9df0592dbdf2e2bcc4c79cc79a87cd31fa64de3" },
                { "ne-NP", "dc9a7b8d5cb1260bba4d591d3492b1dd7644f4d28bd5c19de264ca122eb38263869172a778cf72021e5d811649debca7c0b0126fdaf7c66a24b67a8185473ca0" },
                { "nl", "2be515eb87e2d7aeef98426ee1af90188c5e058b3b279f7bf6cb788aad73d2255f4e4336f7e2f3a9f8252cefa0bbc26745ac3c2a161e958ccdccf07660fad2d0" },
                { "nn-NO", "b868c6878904da3cda96f93bc43312d79de1e08dbdc9211182f478e88803eef0e4d5349c58e1cdbbef95500d439c068940f29fc21ca79c65eb8203ae630b9d0f" },
                { "oc", "b545fa04c592c3d6dbc64954b21774ab7f76c9db84f23efbb76d9ef7d78bde2981c7d4c766e08e1b5060fef4f0af02b791e391951f4756488397dbb856c26ecf" },
                { "pa-IN", "8ae56f63716ce8241cbb54bb620a8991d8187b8a38dfa01f968d9df6adfb88d74fe69d40c83a3660ed868827694bbdcad9f5c523ec926ad2ac1435629260acbd" },
                { "pl", "e9f5f0cfc55450e9fddebbb362c413305ffed76aad7060f5a0f90f42a948bee0b50adb187477c43992e49070d3675ca99a11d8e25ee3f47a3a1b7c784dd59eec" },
                { "pt-BR", "c86636503ed31db6573b77aa4fb1bbac4fba7feb2bbe202e468b116f59d5c00bcb5c1e8537a538679f92ef8c2ba5b0ff2c5a446041f7643a0f4fb858dfa3b1f4" },
                { "pt-PT", "983c6cc116ee1dc3a5e9590300a146a34226ab2e83ad2a6fb1b147fa4264b93b74ad00ad9c13efe1774798335a6907ccca8ae04783d4c4d2291c70230f55e284" },
                { "rm", "2bec010ecf6b96a35f8fd31b4d01e3a236996740800cb9977834e48ba65b9a7f182816954941cca2a8c08c4fa1620bbe0f249623c92d36007f98f85d0b28afe8" },
                { "ro", "8b88c0158b7b9075c90ac70d277ff530ae25e4a9368d6885d316aa9d80e190ef0f1c3c8f00ba1eeed8d6a3ec64f597054b99d578a12c77fd576930daba04581b" },
                { "ru", "d08cc4a11163c3c5bde9ee346c7b087790441b1485686d408d04a5a5596098c9d6481ae2fe5bf45ba6f0b6eff5dbc98a0a0304a1af99164a6e69aa3ee075676a" },
                { "sco", "99c0e1fad9a0c2c998bbf3bd53528edfec83f9edaf1c0b8a3cc82189eb1c993e32595cb306b708f0763ddf44604c854d568083078f540cc7b407c938fd03dc01" },
                { "si", "5b93fab73bf672bbf299c5b66b2febef89ceccae77d092382874e352d0d088d40c41dc1ec011db1baf153dd67be39665288f4bef0a22e4795d1d9161f85ab6d7" },
                { "sk", "1a4cc9df1654faaa54b2e2a4c92294967adb1ee88c7e0a50867bd33bcb1753d1423a835eec4882bff0f194bb04359228e361d4d2fe85af65410f70d7d239bc2f" },
                { "sl", "c9ce23df86b64a1292cd63f6ee35157c152a3b036c088146da290285ca1640b590aee8f000e4c5bf0f4e26296781e5c341ae43ce0a3cd7a935def1e59af537ae" },
                { "son", "b84ca02a7e34199834760448e75eb634f4e08395d52e335780fd32e468273257c10ef1b121a9e28e6e6dc24ac95fb64cfd6140f628f42cb187395d14e853a8b3" },
                { "sq", "d6bbb571a1abe7f3a3a101d706742a696d21e990984c771b776b193b5b510349a8f1a07351ec8ce174485732384a4f18eebc1d6b804cc9233f19bf74f491d464" },
                { "sr", "334efc03f0392917d928e6df0843228ba7ccef6430fbd92ba6747125af845a1cdb4ccdd5db8761ad07b7dd3f85235e29b38543828e5e52e4ccd944467b87af0a" },
                { "sv-SE", "f005787f511f2ae9045bdc12bfd956186c3e8876484a36720be4196c258e34077bfbfce634aec87ae0aadda0285ae68cd1668f1e10123cb64d3d6ed82793f28d" },
                { "szl", "8ec541b3634d3c4ffe481d3be7a4a2aff9fb1ccb6084e9cad16f54a4f39fe8ab1eb5723aea8bab7fec69fbd66f022fc47022bc46a765537c442338f7da5c4b2f" },
                { "ta", "19e3f3aad9e7abd47bfbfe60c80deacdc1cc23a31400b53f7b032fc89b93807dafe24d76ab613565d3e5f24fe6d22e460b7e83a1f8aeff9a0d599a97aac30606" },
                { "te", "a40a66b50bc264d46589d64881c223394e61e23c45176e0b3f942e3fbe6fc16218e4b271471d86f136447a9c4dfa5e6496ea3af35538bd17a86000b0c9a791c5" },
                { "th", "e74d97a4fcb875256023ed5aae4dfbee88e73332f803f04b4f310b5c7c457e9652fe06fed63092c9b254322d3f95b07abe1d2fcbfdfb31a644f0978442c521c3" },
                { "tl", "27409a628156172843d68759b306fbc69ec6d7b8e58e2697d734de4a34eebd4cf89dadb8e73871e514f08348d1bb9f19aba6134ccaac0a77de7c648ff56c1678" },
                { "tr", "136be7b3ee8f9fcd911eeb623896d443404b9a5b2d64f894468c9fc5c287c4467e976f9c99fe5bad38bfdb42843d8376411156a469e29fe30245a0ec9fa72f2a" },
                { "trs", "f2352a227de8b4d15b6ae89ad9f7b50d768944bbd14c7abd8aa740ca0e5921a6921eded8b9c1ec619f0d2822a1d7ecaf66287c5b0593e51f73979de174cb0dbc" },
                { "uk", "d63e76ca63ac5c729e591dc9d5ad6f3b6e9e20aabde77420ff38e71f949cc17a5f07b4a441e73ff89010a78cadf04f2f14285ed9a07c7135830f549630a73b34" },
                { "ur", "8f866e9b65df256908e4f557289ba22c845858f8d69e5e0532bedfe93745160a5b2a28eea3f39dc6c8f2d47925fa760d9c154969964653cb896072dbff1adffd" },
                { "uz", "b6dd084f7fd5d697b1681bc77a92d6a46d0a9a38ee0ec5661a25e2c06a9fa008504d6fd27bb9796e8337ef75031fb8693b3de8f685061e6a73a9f2c25b611c1b" },
                { "vi", "b5833fb38a629b5d83d602c93b9e9d3ee1419e82a3740d8107f4e46b5b3e93518a92ad36603be97586a1fa9ceec2bd0aad35977aac6ad2a662a970869d5aada4" },
                { "xh", "12736c0b4b1b5e9805b816d314549b1cf79fbf99d43082eca4554bfbedcfb0c2145e5ec6b64fb98ea3176fd23295a76bb368190b96f3a9dba7256f1397d9cb98" },
                { "zh-CN", "2e5d36e389e7711413315d872b695875bfcab5d28d7fd4e2b440501d5c74a8c2c5bd2c4e16619d56bbb5d421681676a827ea4b945428dfe7e1fe4458da84ab45" },
                { "zh-TW", "bf9d34c27f980d306d7c7fb844f355d8a00b73bc460e87a075dcb9492ff638f895d297e7303696697d820ad1d4f3dcadc1d1e13cb5995d1c1fc17a8fd4074166" }
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
            const string knownVersion = "91.5.1";
            return new AvailableSoftware("Mozilla Firefox ESR (" + languageCode + ")",
                knownVersion,
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Firefox( [0-9]{2}\\.[0-9]+(\\.[0-9]+)?)? ESR \\(x64 " + Regex.Escape(languageCode) + "\\)$",
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
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = WebRequestMethods.Http.Head;
            request.AllowAutoRedirect = false;
            request.Timeout = 30000; // 30_000 ms / 30 seconds
            try
            {
                HttpWebResponse response = (HttpWebResponse)request.GetResponse();
                if (response.StatusCode != HttpStatusCode.Found)
                    return null;
                string newLocation = response.Headers[HttpResponseHeader.Location];
                request = null;
                response = null;
                Regex reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
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
            string sha512SumsContent = null;
            using (var client = new WebClient())
            {
                try
                {
                    sha512SumsContent = client.DownloadString(url);
                }
                catch (Exception ex)
                {
                    logger.Warn("Exception occurred while checking for newer version of Firefox ESR: " + ex.Message);
                    return null;
                }
                client.Dispose();
            } // using
            // look for line with the correct language code and version for 32 bit
            Regex reChecksum32Bit = new Regex("[0-9a-f]{128}  win32/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            Regex reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Firefox Setup " + Regex.Escape(newerVersion) + "esr\\.exe");
            Match matchChecksum64Bit = reChecksum64Bit.Match(sha512SumsContent);
            if (!matchChecksum64Bit.Success)
                return null;
            // Checksum is the first 128 characters of the match.
            return new string[] { matchChecksum32Bit.Value.Substring(0, 128), matchChecksum64Bit.Value.Substring(0, 128) };
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
