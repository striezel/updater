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
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using updater.data;

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
        private const string publisherX509 = "CN=Mozilla Corporation, OU=Firefox Engineering Operations, O=Mozilla Corporation, L=Mountain View, S=California, C=US";


        /// <summary>
        /// certificate expiration date
        /// </summary>
        private static readonly DateTime certificateExpiration = new(2024, 6, 20, 0, 0, 0, DateTimeKind.Utc);


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
        /// Gets a dictionary with the known checksums for the 32 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums32Bit()
        {
            // These are the checksums for Windows 32 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.4.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "68ac99894b1878b2183a0c295efe174bdcf379f28ba4a4513f0dd7d66edac23c90d561990e42e1677286f2beaa480b9a0258b7964eef439b4fbbc85464d2e2ab" },
                { "ar", "43291ac31fd5061dd135e0d14f4d9b6ff0ad59b5f4907e9031f0ce87bc5ae4870a89c51ab7481f965fb2a22986601597a89bcf52bbb21198b97c348462e88688" },
                { "ast", "275000a48c7f7c7edeb72ff638425e03fbdf286ef5788861531b533d47d781da38d61a7c085886c7f0b73dacea62f446572a1e2e498a4862404cd7eaa8a59553" },
                { "be", "009dc846ba98c2dc99f7e7ca0f521d03e2c3dd838bf40dc24c21450e651e0927bbb8baf3214ffbe0da913ba34347baab7ce552bc6ec4491ec33553a12c7c2dfa" },
                { "bg", "f8f9b9784cc1badb9b73e9fde713180ef32f92b1a2f670dc4b3e2f332520ac772560a5318d39b3c88484fd12306e1f3f7fc2f0db8ad42ccbc4eb5dc292e2f2a9" },
                { "br", "9877ab9d8d90fc7121fd41c439919f8b140fa9ba5317ccfe59e45d9065563fc8c9f3808c3ed601d61218aa8bc3c2b2c10d1c519f7e2ec1dacfdd23854eee1c4e" },
                { "ca", "36cc844d2125de6c0d175e465b9445a27bd27d8f508346c0e2b2667953addfcf8a11c804b73d12951e72a9eb858d7c07e0f724babc8cb340f88803e43ee3de78" },
                { "cak", "7bee1053a5ae6aff1f3e94c54d3abb39bcfc262ca67b09f4aeb6b2d21cd9723382677ddcbf42d041f4bcf439125f309dfe595cb8c021cfb2a3dbeab890b6e69b" },
                { "cs", "7fac5322d34387d5f1f1fdd5e1945ba1da183112bd294f33b8eaae560193023d6121bef8f5c1690f6913050f7f0eb314c4e125294ca7ee1fa0be750254146126" },
                { "cy", "312d0e4fcfd010445e329344d1b03b2da46ab2baf7ad97d40999242338079d934f6a71f061a33a309b15f915a2f9aa0297965c9c0aca8e2e0aca47c143c0134f" },
                { "da", "768aa59286e137ffa791b991cf18ee28fc600ad2bef7da898ec325af41b89e138faa5e128917d449f35c4c96c64f82591159b8646ed2ee3cb7c037828f1fd93d" },
                { "de", "fcd7cc4bdae001b17c1ba34fc013081125b2c86a3ca57b05d01110e0d70ee8c753603a1f9c0e624de7d244943a1666026be85ec525cafd6fcd75f4c7429e7d04" },
                { "dsb", "707aebed2a1f6510ae733bf47577f8832386e3ff59f04893f33eb71c642f46cd2e0f7727c9a7dd4c196b18061e1edee9d9cb1980dfa246f1adc6e1f612841400" },
                { "el", "3d12badaf04c7b1ba368d6272c0281535fd36d86570d1bfb0e9bf53c3cd86c66dc8342f78329ccadfb126f5689dfec3c56f21b1befec1334cde791be847549d3" },
                { "en-CA", "88e73872968c924fae48045a7398b791e3b6555a0aa8a8c99f350a6f00e55eeb0011accc3eacedc317ee59fe4d36fd98ee7df08291c250c7fafb2faab47d96bd" },
                { "en-GB", "5e21f2de46b3894311d86aa7de99b3d7f2e3e3a90ebc5d5d566727673687a51adbd6a4641e1b27f93ff1590390e93dbaf6344668a9f8a9ab2a64fc0695887ecf" },
                { "en-US", "ffbe76645463f109f2a84e91c11569c0026c1fe95f2346bba390ccb1e86b32d9aa698cd47b893f80c3335ab2cd69095ef1b28d5d35834a43325129bfde942c6e" },
                { "es-AR", "bf2f32d1e00dd1160db0017521c27939eadca42e42b03f23d92c0a14c0fb9a2e70fe70ac7118006e7612eb6c4022f3095619c4fddd7d0ede620807605be9e3b1" },
                { "es-ES", "3164d89d31e14bad144927caa43f36ec13e714b208aa1b0fc7518a14a777d1ebcc16f00873804ce6d6b17b25b8b9238f9be8e6b8ef8e4056876968acf52c5db7" },
                { "es-MX", "6b4770ac23a0f858b349775d4bf2e7723ebd47d459494d1f9fc508e5dbc7cf536e1baf668bf147937f3bb96be0cbd7bd78d7ab3ccdd3ed84ae7e33682c5d0e3e" },
                { "et", "49e4f2e946864eeb9b18cc35ea3a75b285ce1dac3ff6075ce8f71cc5d3b45301154766d561cef60fa8535151c2c973d6012fc337f3e22f9874c6aed63aca214e" },
                { "eu", "82af37849176bd31222fc2483ebd26a54551b64fffa733261f4d58553d4edac7e3b7dc676d3d083359823e2167ad9e0f8f30e7a4f4e8f751874d3d4434abe3c1" },
                { "fi", "ec5a8770becaa20c0787a5f1cbaa1a713e046a9ad60a309e74331aebc5299c16b7548e84351da08f200193a042e65ea08f6a93632d2054736b75f7e709732bbf" },
                { "fr", "d8ce97b94ca8e8c3cc9d0673a4dce2092425a6473c8fec6cf052ce57661ab509a05cbc758e2925300173b4ac68083109b15e6844d791174bdb5c7d388d690908" },
                { "fy-NL", "91327344807a9051876d8cd6449d1e577bc83b9e9128ea4baacd81e6408118717173d6019afab5f3867fa4622583ce228dcf0e7b0e77869d235693a57c62ff07" },
                { "ga-IE", "a15256de922cf6e589ac57f7ea36d65beee9ab525fb1e6c65eeb5ebb77146c773d375542c424274ba123c8665ca835d00e03f9398ba21e2f3f9a94575f6accf5" },
                { "gd", "5950269dcb1a6bcb20539f364752c24611bc02c0edfbf969f6384846d9f8ff37a11b75237126029074bd75e86469cabe868dc2a864c479876ba908800f71a513" },
                { "gl", "277191456e7ea7079fbcc147508c7f3079a76eb6f7bcce7e72cb745d33780039e4911d5d0d51be2b47dac836a753d600aa97109841053f3652b41a8cb57ce0e9" },
                { "he", "55dbb18646d25807378d070145f81312aab290bd4c684d02d7c5b6ca9b877e9dae7fa1ce89ea3eec0d5322b6a1f60ca2d7334c4dc5408657467f2c10db3df958" },
                { "hr", "fbb6d27746e0540227d203c1a50269342cf18447cfab9b644e894175e5c4a65c839b6a58a342c4ef106de1a10d19c104ad6c6644d1e8b20db0dee4967ed1450f" },
                { "hsb", "9b2d04516411a08ba0a6386e316df62701e07afa60cb34754b81701a3388454121a22901ca3d323e040a5908bf646bfe06db131f6a7cf555df53475d6121b331" },
                { "hu", "f35e6f6a49cc1db0dd7d78ddf76d601766de1466c9095c628c5562de520bd9ca0d8da20521bb725ca91412ceca7ace1b51d5fecebf5838725754c5cc74c7789b" },
                { "hy-AM", "5c8c681c80a28ee17a4cb9f708de7f7b2753a09a49c4a80d76a2fd051a96ec17e12290c5227e13d584f6ac35e60ca54d5e951bc4d5535ecb78926f8ebf711e78" },
                { "id", "c7caf6ecc299177d301188f9081ebb3a884121debcca08a26b002bac6d6b082ea413b990385ea007cf04ab494eaad9fb713bc2b702e189c8173373884e5f3f59" },
                { "is", "190e9c2629f31b3964cc389e0b9e709f6d63cb51d22eb342ae2ee818a65f95f9d84d75dc9bdaec45fc113f84d11e5b84836a78923fd07f70155e581a0eee0f38" },
                { "it", "666f2c6a31aac45f26427fdac21250de74b703e0751b5440996b1115663e9bfd16150ebdd1f1ac0d3941dce0edd32c16d601fc3ff44074f3a995743200becdf1" },
                { "ja", "4a3bddef267e8619349c0e0e3d0d7861fa58179fababaf3f8c5e15a39ec7b34a7b00ca855e4e21d273ec6f88267f8a3806a6bf4d63333e0bd1fbb8098b84778a" },
                { "ka", "2130f4f91a6b1c3232ea1678b0e4fd22639be193f2882ebfffc4fb5d9b669ec9b2689ff16927a2b3591762ea2fea04f833b055b9774cd4c1d3efa47b8b21d533" },
                { "kab", "f8b8c4f9d91de1feb679e8920b4c99e0d358dd6ec03de9dfc45a232cbc77c159068dbbba651444c8119d1b0300f4330c966821a9825499b4b511962f09650138" },
                { "kk", "755ea736517f19bddef8b6ef98b8ead9f2f59368ed25903d6c3ce49c8f71bd061acf18d81efeff17d64133ddbe61f31e9fd58504bf5f046f1834cc27e73fd138" },
                { "ko", "13dae0eb2fbe64d6197235f5f24ad460ecba28dddf25d93ac5d5d96e46823f2ffddf16b144d3cecff4ca83e2169f1b293ee1f335ab63e5e7fc903b857274f69b" },
                { "lt", "5272d2fefc457158d5c5906363512cf306ac0832e0594148a8929da2c42793a74da49b9783829f4e9cb50f56711f6d44cb79ed4f201230c3d0b4530340548e39" },
                { "lv", "a4582ff9e0027d6cdfe296edb5b3e76e2f02c8d2ae508048b90cdbd4b3af3182c90d448e6c5f5831a82647bb103acc7bc1000507983d676c1dae89ca49cfa1dc" },
                { "ms", "2a1ff210ee6882f3e167950c97686ba43efc2fcfbdbc3115306091c8139d6f6a943879e925dac8a5d15c9389f156d2c517f6b980560b58bd1e17c29beeba7a36" },
                { "nb-NO", "8065d852a299a46f1ab3a25be7780ba697fcfcc457c407328b8960b99aa6c6e61ced4a1ac4bab31b4a1742ab74d1c2d6f005132b8766eab9f4589b092c187e7d" },
                { "nl", "d7874df58afaa77be360356dad3c7a40c5f43d315ee112842c3d4b71d2b4a753d7fe911581ac2bdbc5e5e481ad9ed1d76e13fcd39756751fe82114978ffe87b8" },
                { "nn-NO", "3be33830365c1ce2eb60fc163ca895389f532925dac8ca41ed65fa72958a7f96ea399de274c70563080f7417769542ea10d9c4e76f13ebefe4fedc2aa6fe3bd3" },
                { "pa-IN", "600936fb31356ec47c658758b9316ab1c58993f7554efaa1664ba4e618ec0ba37aa46bd57f09f834020097efa69231314b0334d3fa2c602f5e432437d95fa509" },
                { "pl", "ec6c0cfb1af17e0f8b653e8dcbaf6fcc3e0258bf05bfeb231ede7f741fecc72804775651af8b68f98d63dac15d9f20d80e6db59237cf9975aeced4aaa70a7d3f" },
                { "pt-BR", "d73d1d70335f21f0cc9ef59e7ca65383540baa1a02284e71a4054034e61fef7253c1649721006f508afd51c1e9e8c09e860fe99a2e3588c1d62f629698b9c0fe" },
                { "pt-PT", "da9388cd6476d01812309945606b0e579fdf13ad021c1bbaacf0494c2c374e7cf2d01d84d728eb659a4bcff7a506a2872ae267de2d89c58b58ee0fc3e99874ed" },
                { "rm", "16632b361e4e8f5d20f19fac7e0877d722461f54d0cf992a98c2a8b3f7cf29782ef5aeb10bf60ba8fe85519f8a9bfdc8b068b6089b54f395a3ffc5408dd41357" },
                { "ro", "3898206d5467586dcf12fafe6a2d57cf118d13b1b3432f5aa4b7035c155e299e395cfe0cdcc64e3db2c73b3a7b190f484ae3d8a96ffd286a0eba49da9e3c3ad4" },
                { "ru", "d4852ea74d07e15d9675c3fd572ebb2a83f484183786fec2f43d91d241f48bbabf1a784e69dd255965a835f25f6dc90a827c21f7f84e87889eaff55adac1ee9f" },
                { "sk", "499f12dd08d45a270f909c6c13639eb8c726471cc861fd8a8ea8aac6989a2874311745095f8b0e46dc6e8f32111c0ecb7c630255daba78f9e49489b5a846119b" },
                { "sl", "92d58811870ff4222d3116d6c03e27afcde2c51439351e0ddc2043b48426564c6bc8d217c718e105a0475fd33446377852d6168efe1cbf013a95b69b5d71a9d5" },
                { "sq", "0e6075bcd807f9268a82d057b0e41068da4f24f99034c5462a1979263e908f156b9a9cba183c803759ae893117ff055135a6670a2f125c51fc51f84bce169181" },
                { "sr", "9a87830549602dbc001c28737d965170f938f9fcb7afe992755c611e8cee0354a4b4c2049113c9f000950b440739a831fcd5cfe70a25582e4a0a76e2481f1386" },
                { "sv-SE", "8e5c8a940c209f1553aa32bedd4c395fd3bbe09f0230614169f233e4005509fc067e9abb9c11d6fdf3976e6a5de350d25f37d5db151e431c612a8f3ebc607fac" },
                { "th", "f88272181bdb8636af4c85b4386d6ce7f035e3110b73d0f8d3210e2114bbdca630429bb8df5fa3b0367b20b2542bbafb4b01fb21c6175e93d99641b311bd98d4" },
                { "tr", "0d4e7d58e2183e5ccb87a476e78d2f1dd107d1b5c55edbbf8f0b95ecf99d7f8e62750e9d0a50a832820dc3ffc1da3e64d5a1e7460f972b11669bae2613b958e1" },
                { "uk", "4c29da97a7da41cdd44ce00a1c62055a377692383e9550ba6e5c7217cefc61d1823b9c1c2a46dac1b916acae58cb33a1560249a2ebd0d34daeec2d8bcc27ffea" },
                { "uz", "42b298c9ca1a67a475e8c89171865a71ffe43683a9ede57768bec3b4097cf31722b08bb3cfef35b33729d170935a85d419af64b867389385ecb489312c595cb0" },
                { "vi", "e3adf4b7e00840883b1995629dc01a9f98a3b8da29b75d5fc11db0d94f707c7f883e06655f6eb6cbb07ff2c6757d2c851d6a774202144955ba1a6193ed9c8dc5" },
                { "zh-CN", "68e1491aed48b879494e47cd4858d4069af7805340abcbb7deb4230e769c67d432585cd247574104ec2603633d988440ad863bac0b6477f172501feee46cad28" },
                { "zh-TW", "f7ba542ad5e2b6cb5ff055c1c985f2dc4152ab5cee3dd9ad2dbe647fdb7a93a92659339ced8fa303416cb3646a07d80269edb7513de3e0a7d4975a1f7930dfa3" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the 64 bit installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64 bit installers from
            // https://ftp.mozilla.org/pub/thunderbird/releases/102.4.0/SHA512SUMS
            return new Dictionary<string, string>(66)
            {
                { "af", "375e137fed7e9cfcf72c018d5aedc9242d41107dc50633c160c37a82e67838a34eb075392581cfbdc787d1e4fe26811af82a94a735601131aafd646c483ee9e9" },
                { "ar", "2de73ba04ab2c091ce1948426e686b23222c908efefee330fa5cd21aad14a34325bddd3dc7c937d56d7b828998ed7870fe42b4caba22420ef895d9ed5c38e783" },
                { "ast", "23f074d475b412970f105a3372ac792e33b184dea0522c649abbdfcf9cf115ec2c3b367711608dab7cc28ef1f9abc1a740c9369d6a8ddd5d3d2ade5c0b3687a8" },
                { "be", "a3c547a760c70688c34ade05c68cdc0eb5adf936f4985f7c8252fc808f3a7c077738781ab1e5dab2d7a3d412bf622ce200224013184209c988623c3f867d39f8" },
                { "bg", "4fa3300f6ea78ee859152334981d6c0eda7a81b73fdf4e9eb3320e071a053968cb91ad5e58a211e7cceebd50a8ca51fb6fcd1a64ae09db82a2be8ad007c64d4e" },
                { "br", "92f88f2e85a928c0a2244d6049877ed1213a20238fe38d1d50d74204a47d53c730866d1c9a6f06c3e2fdb6452a8b2fe23721cdb77863f025a29222b07d4a96a0" },
                { "ca", "68b8d379468892e9c6e118b310813051239e32fb0b8ee1c7687b4a5bb833ca82ee8f32c7b8cabb7070491742751ac0d39eec0bdc37bda4f2014e289ad7f5a5ac" },
                { "cak", "1fbd3175f21fbd018f2c376b7e49ff046c88c2169e02f22564f8a4d41abc5696a3852bb92a519b8021686e6445322436bc881a9bf57f53fddf8fdf1f69899c44" },
                { "cs", "38de53e17a52a54e48abc5d3382f9f8b7c8f750abb92743511923972eef9937c5451c891711dfe39d74fcc2982f631fcb322ff2b86ff9dcc99daa734b7686e0b" },
                { "cy", "78b317fb20e3d2ab4b433003b20fee6be062139dbc594915d4242411d28e87e0843889683df7f9cf579eccad56b859a23dfedaaf59c7c71b6bf58c83775ee6ac" },
                { "da", "4b2882d4ffa14d5314d336da53506075916ea6fa7ce6315b5cf706a2a2df5c0ae73e789b5b099ba4d6d52e778059382a053e295aab56449f68ef54733403dc70" },
                { "de", "c2854868e2d5f5520343132bf536f41559fd32d2bc0905332fd287f1e2223f0470e053ff47236e5f5620c689d66c89f4e06eb6e6970032ee9165587bf3f5b31b" },
                { "dsb", "6dc80fb6236eb88536a325f30058d5813f1526566eedd8f0529048f170085e7b9cc7fee948c4ee71d14aca6bef199dcbc333c689a31d843813f4efe62b01d42d" },
                { "el", "9dcb7ed8d41704a05098e6c3a279f52e06e4316ed8c7a0114ec23c84bdf5c4371ae558ecd6241a820b4a68f632821b831ac68e8c57be6f925fe3a67d9372cda2" },
                { "en-CA", "2bce46f6a577182dca839f04b549b3c097e3f4e8cf7e5ffdb531a96f0aeb8c95c5bd2395128779ddf9c3e4460a24e391b4253099f046e5494c0d960c85902306" },
                { "en-GB", "ba50bc0bd370517df65142939e9e0c06271f2c680337ccba2fb40da7c083c89c1865d0be0c853e047b2cffca1cabfc1abde2a85fd369bdc1a372a6d1b1309086" },
                { "en-US", "202df2f14335c72363d8cc689fbe7a930cb7002b1b9be1a5c14d7c7cf1fa2abf98f8b2d558c4ff28acc6f4c8abd0d417c297cc76029fbecebc8cf8323a093b14" },
                { "es-AR", "2552b7fea4ced6abf1d080b6edbec38833507ba3e2912aedd589c7ff24ac84c6fbbba41322e92651e5b0f6998bae81a8b61277f2158db2739d4268ff3d87e469" },
                { "es-ES", "fe3457a7f45f81014a5d932d065be76436b7609a649e6873c8ee4b7249e3969526a466eb58f159e7dd6e4371599c8808738599dd261b3585fb2b044084f768fa" },
                { "es-MX", "2b416d51b4987745af18fe19058cdf1e270b7a36c5c666ebd80d57362642de42e13572a5e78a1e471a0da8a3744cd72147b43f74c0c22eedf6a42d5440d0c081" },
                { "et", "a40282bd8f685f24d038d06ceee9959cccfba19664d7d3f1ce1d27e75c4fd6758bd2d5f2704894b02a252d07489f7ee8fc72668b3018b8a20c6cd66bd12342eb" },
                { "eu", "deef3fefbc4f484bbb3a3e27c5bfdd7e732503690914fef641e0041704ad4bdddb9d2a7aa7fc53ebf4d21099ffb5d4cb37ee155f513238a0609f0f277ddd95b1" },
                { "fi", "1412fe46b5b07d761b97c6acddbd6a25bbf91d055530391f1cf9370c71e7775d7d46d193ec1a756eb8e506362d1556016581c2602e2cafec725b521513c8ff5c" },
                { "fr", "32273739f2fd2bf62643e25f6d695340a3ae9981f2cf8bbedc76a62df9393c5d77b44fde86422106d2c3bcb984dd106b134b87ddfdba943e80745605de3135d7" },
                { "fy-NL", "3791fa485e845791787025ad843e43163344e1ed1609e2e82fedc3e0319b15aea2adcee44b3d0ce99ed871067ce0b3f0d47660c9ab0fee12567a5519c30ba880" },
                { "ga-IE", "f201a74621638f10891f671493c97f451b7ea506d540149ecc19f1c99960b27bfab39f2a5d3d002b188764bd60a1527f4c2fd8296a048684a202614c33c18990" },
                { "gd", "07d34284716e692800cbc6bcbc737e1780e758da7fc20c56dc0e097c216adbc9b9fb1660c3a159c4803be9d6d2ed75475414c4a4840c69d0e54e5f577958f1a9" },
                { "gl", "b9a015fb671de5e3926b7553c817d00764fb189dc09719df74f7948d7606a9197b2f1b9c0e498592a50890ef08cbb76ec522ab313d1fafa186c6ba2a0f188c84" },
                { "he", "b68308902aef7da7cf1e2bcb490f6de06b61aa38f3adbaa9395b71576a66ae67d272b3daa32f1529056f455cc0d249ddc8f61cb25485e61ba75ec1199fd9f3f4" },
                { "hr", "620a704c793addcce8df30809d90a65dd3447af40baae73d21552b94667c582a9dcfa37788688f543e617db22da6485e4f5e0e7e35cda801ebbe4d0a3fd222fe" },
                { "hsb", "eede952640856b8c5cdd1b5d7ffe40bbbe65ef875555870b8dd261a049e861f435d8624c7162e51a0a5f61b75306c536bcb82b647308fc2a7eaa0f2d5641afb3" },
                { "hu", "d13f65464db66bc6bd679ba1fd709bbcfa08924f0f1a6ff4aaa72a8c5015029a9ea2b3ded0e310248d5ee8a31580f53db55f145f335fc928d04fd04f58792d1d" },
                { "hy-AM", "5090096773f73ea998f94fa9b85e38cc14c22a88da0f74a873b18c4946ded815a22af7a66f97fded0bc3830452bf2faa712a2ab31e08cafc1a95cd4529d09d5c" },
                { "id", "5e5e2da3f949474f6b10f6cac6f6eff2f04b6b4b43e454a9f17a4abc549462ce91837778e602812d545cb8334b8d04ae4cb25004e51548d81539a0ab1b181b00" },
                { "is", "cb33f508bf141ee08b643cdc62873a338cefc89f2b8f4bc285a86d4c6e11a01fa53efd101f0363354285d2bd3ca1316ccf45515e23c9526608e7cffe7468d029" },
                { "it", "b1fa3bcb573452643fa466142d25f4363ee6cba5e0c63cedaa2d22cd428a18eaac54d13e125623d1823d96cbf743b4cade815e469d82951622921ca155b212a7" },
                { "ja", "6d6b1fa85bd79b617f7b9f8af79d26252659cc21ba22d203c215816945c0ca80a726df895d0852cd1f250cc3eef13437ab0dd4fe51980c844b20ed2bb97bcc84" },
                { "ka", "76044a35f685a57343249d156a550b3d40c2b7f904878d48f61c983c02ae70b6f1cb7dcc835e56717ff69a88e1ab7f608efe417731375eb62a878da0b85a8012" },
                { "kab", "6bf7cd777ed3a5a369e626255e6ca7f21895c1588026519acbf498e400f572c7b6054b2ad7447d1ddd66f97c7e038c899e7f1aac8f08ea09f6b5dbea55dd9184" },
                { "kk", "e21316c27461b50c93510b3f85c702dd998aef9ef74fcd3483a1e6017e527ee149c104c55897a89eb033fa9967105bc248aab6d9fdfa090670ebdcccc8869f9d" },
                { "ko", "8fa0b5328e66fc4b91271af1b597aeeaec1f2afc006829c76b418b2fa75e68da007e64d48c9cbe6e3be27898cfaabbbdc5beb4b7fdb28cc6590ddc9362134fe1" },
                { "lt", "1984dd64191a04562402a5067af1e58f91935838df18c91937658c75fa30d99efa20718a809de04b30851f175e26fbf99af019cfce4baa991cee1609f9688ce0" },
                { "lv", "dee2e51273112e370ca63b05a1687f01aebdf869f82a6229e7fbfaf8e3c513ff6c6e390caff6ffb16fd2dd5a9051a63bf846721b55d3348da76efb3cf10cded9" },
                { "ms", "abe093d429d3b48efeba52d10d4fc887a597d9deb384512f03290e24f823992221c0f3f2298d28b161bd07e8d28cbea8f4ed98f85c2409a3cadda0f636869d8d" },
                { "nb-NO", "78fad06e00f88d27bc66e8afa691f94cbfbc397d8e489411a433089fcdd00bf592bf2c52a8f1229a6f309cdc67f2db0c9b94ac557c1a38c822ba270bb3dee10c" },
                { "nl", "bdd1c34722c0440cf4858abbf3e4677509e104ef878511acfd8ea96e5820d89296ad08116d3263f786ab8e51eac3e4f6bf8c66d390f22dbd3905502c653fa9e6" },
                { "nn-NO", "bad73dd95e252689f551a16fbe557fc4c5f433f6c7b2d5372ffe10b595f2be847958f9767e98f372f2a09a6f0ee0454ce7c2e5199f9a20e9a08f8ff8576622e7" },
                { "pa-IN", "177566fb44474c1edcde3a35dc8aad350f30f72bf80046d3e01e9e6df11acedef8e27b94b13f84c1ec2ed13b34069f71c4578d236be5b81e0001b4c344d497ce" },
                { "pl", "8b99d650ce33c547aefe296d9f8d318ac5b6a5944370751f7b93cbf6d97596bb1a33cbca6772c754cd07b55aecbef298d294353d3978324d933ddbff44dce761" },
                { "pt-BR", "0c9728e97f1f423cfc911a91b5baae1b444948016d8cec9f181fa9a4b1464a807a8725d07c7366967a611c2318116058acab97d69f464953e5137e2f6c0c660d" },
                { "pt-PT", "77af5bfeb48245a02a691e4b00c3c98ac0dd3aca01ba0b5274bae50c8478040187fb16c6c2796bde2e8210966e8a6fa4b3dccf18b9ff94ed6a45fb4acb43a3c6" },
                { "rm", "e0f0ea615514ed5c27c0cc395ff67a30ad1f9a758f15cb45ec2a11f1317cd4e587dd81af878cf69008eb7bc9c64a3ac89d39ffe05c43376fe0ba6cfaa04cd703" },
                { "ro", "9567742a5b0f8f2f2d42623c5651c50d3fb7fdca80a4c9bf88d877cf623fbbbe4c0cc803b4057644b3d0a4a2041d6bf0cabdbfbf7c2c5725f44819aad9fb8296" },
                { "ru", "818463311f4be1e594a49138d15a9a239a8b2f0a886bbcd7b5c9150ea35bc19282b84f01b0875635c35dd89c23ed806ebee219ac141e8b280b17a679f0afb0b4" },
                { "sk", "0a9468916ff67060aa42091316b1b3e17604e39b277d7c3c963501bacdd2178a7b626373b68c0b540755d68c5b28979c6fb227bb822ffb822e1fddf1397eb9f9" },
                { "sl", "36f9aa3b7a8183f0cfe5bd25b99254ccee29de063bb9eb36cbd9dba0d20b550a93310efb046d39ae7a8f7a9b86c01a3731498ec4ac78f4598dd00270dc43c8d7" },
                { "sq", "75438934d235ddda13d11f34e690e3750ff89f75978acb7201d65c521890e872f86584ffdf41661123506e55f347fa423eaa566456d00f546532d365a1dbe362" },
                { "sr", "7f5da41a2bef5e23e0d03b08b6e696f56095ca51150ebf320423553a06ef734107fbd509ac7ff53e9627be6cdb3c8c9d94dd89e48109e020de573278adf90d91" },
                { "sv-SE", "0f16959aab675144a83041d611c25c5c308b302961d87597535866fd6aef74f7aed399d9acf02e4a11b93aa1fbc1ac7114d20e046458fb34fc0fbb60f6efc431" },
                { "th", "3cec0ae96198de80d0cd40b963815197bf5baa872d31b03ab3ad3b2218dd9e912669dc43aba4169b1bd28f7fdb5241a27d59458c0596527f4931a1bb6f59dce5" },
                { "tr", "56d417fa5811d57b9edcb8217535f882b562941820b4a29baf0751edf87af3169c1c38a7006eb352e84a3659835cd6ae8f2b0dfc674b2dd51077e102632ed13b" },
                { "uk", "9961fc130b1c8bac0c302a43a0fa9fa884b75885004360fa564b0b3f68db79ab2710313cc448ca888bac952a1d07200dba3a7a52ef08e66c7c0891da1b2dfb32" },
                { "uz", "beb33a7cc27559293bde4766ea1429d5afe986a51c705970efc10c113d7580cc2e58bbccfa69a10b1b7d90a88fee45fd6ba68e19fe375c680ad0531fdcbf200f" },
                { "vi", "8b4e3a2703be18178e30119bf9f0ac2aa017b8007c645708ca2b0c69c3efb02de3eef6082f731c61d551429476887ea67b85c114f96a1ba5bafe27f6cbde3056" },
                { "zh-CN", "f01137aa92bff6096302a8c87d23fa674b10ab4beb88fd13770832fa023070aa768b4afeae56ee458b476b2a963c1e527f1297b48011e10e8e6772b2456b70a9" },
                { "zh-TW", "31aa415c3c43665c7df44539bedada91c92a98f8ac4454270adc9073c16224d096f8bfe8ea4476b9a6ce5f138c728e13a5036980f4151e75e2c5939268f250cf" }
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
            const string version = "102.4.0";
            return new AvailableSoftware("Mozilla Thunderbird (" + languageCode + ")",
                version,
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x86 " + Regex.Escape(languageCode) + "\\)$",
                "^Mozilla Thunderbird ([0-9]+\\.[0-9]+(\\.[0-9]+)? )?\\(x64 " + Regex.Escape(languageCode) + "\\)$",
                // 32 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win32/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
                    HashAlgorithm.SHA512,
                    checksum32Bit,
                    signature,
                    "-ms -ma"),
                // 64 bit installer
                new InstallInfoExe(
                    "https://ftp.mozilla.org/pub/thunderbird/releases/" + version + "/win64/" + languageCode + "/Thunderbird%20Setup%20" + version + ".exe",
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
                var reVersion = new Regex("[0-9]+\\.[0-9]+(\\.[0-9]+)?");
                Match matchVersion = reVersion.Match(newLocation);
                if (!matchVersion.Success)
                    return null;
                string currentVersion = matchVersion.Value;
                
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
             * https://ftp.mozilla.org/pub/thunderbird/releases/78.7.1/SHA512SUMS
             * Common lines look like
             * "69d11924...7eff  win32/en-GB/Thunderbird Setup 45.7.1.exe"
             * for the 32 bit installer, and like
             * "1428e70c...fb3c  win64/en-GB/Thunderbird Setup 78.7.1.exe"
             * for the 64 bit installer.
             */

            string url = "https://ftp.mozilla.org/pub/thunderbird/releases/" + newerVersion + "/SHA512SUMS";
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
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
            Match matchChecksum32Bit = reChecksum32Bit.Match(sha512SumsContent);
            if (!matchChecksum32Bit.Success)
                return null;
            // look for line with the correct language code and version for 64 bit
            var reChecksum64Bit = new Regex("[0-9a-f]{128}  win64/" + languageCode.Replace("-", "\\-")
                + "/Thunderbird Setup " + Regex.Escape(newerVersion) + "\\.exe");
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
        /// Indicates whether or not the method searchForNewer() is implemented.
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
        /// Determines whether or not a separate process must be run before the update.
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
        /// checksum for the 32 bit installer
        /// </summary>
        private readonly string checksum32Bit;


        /// <summary>
        /// checksum for the 64 bit installer
        /// </summary>
        private readonly string checksum64Bit;
    } // class
} // namespace
