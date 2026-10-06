/*
    This file is part of the updater command line interface.
    Copyright (C) 2017, 2018, 2020 - 2026  Dirk Stolle

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
            // https://ftp.mozilla.org/pub/firefox/releases/157.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "a6e4721f97e97011cfeca8403b0078dddb9789b7b4211a84c0348259c6b390574c36444fd09360ce409bec593f10448b0ec620f42aa8305850726f456530660b" },
                { "af", "b1b5d5f20cec148ee91b4f09178b861e0215047dc75be3638d69ca71799e6cd9d6c3c4b76b47769f4840cc9d232c0b5fbc8b49ff2161bf70c3ac076495b231e5" },
                { "an", "b084b81b4aaddf1256c63024a798719de22a4d0239e61c129d6c87aad027c245770b39bda7bbe0fb4f9b73f2b5f4817cc63f9e646b8a2c14afb85adba5baa71d" },
                { "ar", "7b78ec6429cab90b68533ed95da53f6f078534d534d17f4e49dcc56709c5da20260850ba2666a47edf01ca6cb8f166dbb43bb45ccee8a46b4a103b7660936e36" },
                { "ast", "4e073dd8375f342211d1bc3ff01e2bd525ac0e10e3feb24bf4fa761066f4bf20f8cbbe8e723550a2856447d34e5aad43f980f9b3fb1a40638ae1732fd8bc7c28" },
                { "az", "65bdde5b2cddc2b5bc727d81c18f6261a228e77e552b63d40ed0553ef70bd80d77873073104b23827feeed7b33d6db032702624408d9680a2946841dc0a98455" },
                { "be", "959a1e0f078157a544d047b7e7a7c2a6c84e97943d854587967c9a94c6e3eb9d7cf43f6088d59b3b3cbbe74db0ac7240105fb6a7fa89052704cc05ba25d5a88e" },
                { "bg", "e4a37a3b7dbcc45d22a9d1cd20a062be5fb66f6b1e9a6e70e7e44c66bd961ce02b571c0ec65e116d6cf67f21591d2d246493c1333f31af9792bbbb2d5d1739a8" },
                { "bn", "74d247b69ce0afd12e09266a1ac68c9d45abed2da449baa4e6ccee5631c886f8c55c2e560c5b96e197a0b101f1bcd111df0aa20e91cc6016f219ee869dcb8654" },
                { "br", "bfa46a219152e12d86297f064b3125fe45e81bf8be0703c4d694d325abaef6c3b1447f9674ee0a48cdca21fbd6894794ea2af25326e9581d373edb3127c17ef5" },
                { "bs", "d72f29a13da55807211e908ce1f420bb9566b5e5deff8a9ff8f865159221348fbb74cf3da63b2fe520b8bd2f6aa7622d2e66c8b0b10242c2bbf30004fcfee38c" },
                { "ca", "1c0727ee3a6100c37bf221a5342f70e6bed956093bafabdbaa2e6e1157ca75f1b4b5a2767388c42d40c73c5c72cb69ee9bd2ebc128b9cee8bacf29392cdfa69f" },
                { "cak", "5bfc2d2faddfc5dabd1ab64352c371b9258ac6faf071858825f31c44d2ff329364c3b6e84f311b46b395acee5bbb174a4507c0c6043907650239c3395719598b" },
                { "cs", "16ed32d02aa2e141fcb18b23f9e1d71e7fe39ce5e5d71f781b8fd48a6a6844e1a5c9bf21992e100b2e643dd0a9da16bcb7ccc15fa1d94f13a06844670c6c30e5" },
                { "cy", "c50409c9fb5c4617b23258ac53125684065aff590432879d82f5ed0bbf44919ef1da0c9bc9e8686a1389cb4c9f892a4c91c69ca66a343caca249ee5c67c51247" },
                { "da", "5ca56d7a6060a0b4ff653f19f67463fdae1cd995c67755713b312c5740d90be2e0739ebc3afa9667c646b5a8a804095d9cee03188d83ecdc82f0666a3684f22b" },
                { "de", "25268bf0ffd0f59a104d1a0fe90a7112abcd6041fcea8dab5b1b0defcb484a1b59d24926c6e162cb29eb25f78837a9e3397db6dc30043403efa2d8cdf8d15166" },
                { "dsb", "4af52162383162ed17348bd519950d7777549bac7e9797aa9933bd73e10d26aa3ba7d494de7b88644293e332e8e1acd1498522185787f24488238512efe3ceb3" },
                { "el", "7f6942584a754dedbac2d3c076dd516d6661928f1ae80b793481c928e947ab1b127b107c5e33403b00a842f7709c3470d800a5a1017a9d676fbdb2b01c25e22b" },
                { "en-CA", "a48b0254e38e087ca63c96a0203daa79d5d04427e55dcf8ce2ae75a394d330a3f0f316334b5ba15e4a88dacc7fe6a80e485f5f3ae90c48e9357d86fddc0bdacc" },
                { "en-GB", "01ceccd832f3bcb090dd3a587a05cc14138a48157da8d03f9401bed66dee073ee14cf987014356886275b3c530ab7ae84d68f584ced1aed2cd005e8c0056f3c4" },
                { "en-US", "ba9ab0614bea21eb948a1ce7757a131b82b5242c7f6e1d91936b55713a0c79bc49af4fd746e1f01e9ccca3de41810da5b778289cbfefadc946f56e89e39b143e" },
                { "eo", "c58f35a9c09f27dad4f4b05497a552cfb3fb51c7870b7c3fe343026074585bbebc323dfdaf908fa3c82a3b3fa9141e774acca07dda72b0aeac5eff7504b0679d" },
                { "es-AR", "9a1229957fe5bc5b9d39186c285e00ece621c8b591f9951490ceb5b63eb88e5219da22736e0ea4d96c8a00c3682f0fcc975b5e9f33c66efc805b8846c955f9fc" },
                { "es-CL", "b5d68d9ce828ac44365da13d0b24e3dec7960d86da235f3846e3257530e20479b561ed8a4af8148db7dece09dcee724f5a39ee578c5cf5b19a615b91550fad73" },
                { "es-ES", "08e4d45522f7617e39aff974b7e0cdade9e013c55da9513d975b971052305551dc16e1055d9cf19d7c3b1fbf1de80df36a24c0d05c7189d2b4810597d4921b2a" },
                { "es-MX", "a65bfa92b031fec359d145cb9b1415397dcab981e725eff97ca50b2d876f53b4494d61c65511f883a74aaa656fcc537d56c37af03a57459b57ea56ee07b42c69" },
                { "et", "22a5a26b877337841d0c490833334ee2eb5d61f3c4ead278a2d4dce0d632f8eef3418416cc9b5f839842960023668e885fb3ac1b176eb627195b021a4814302c" },
                { "eu", "3d33829821ddeba2b6a258dd8745abbb7f6dc4e3250d731fec750390c320dbdba5507a6900a24004bd24e041cddb5eaf173e450b583a1972ca39a501efd1790f" },
                { "fa", "e1d90713867f6e8c1dd249da55780512d339da466c2656009fb26096271843a91ff5874acef2e92871fcd95bd671f63197536420a14787d23b5ff8cc0e77e941" },
                { "ff", "db61d49330829105777733f1fd5a3b0994578ecdd4efa2c12e96a584ed16e822f2c91e15f44443953f813d4853a525ea9f159963094de6d759b863c0b913c310" },
                { "fi", "e23a7f068338d9b6a541e42a8bd24d97451810ed6a78f3b3b05e69e6e818c5f6d31c01cc774fb4fef0d858edc2832e52ffe50c239ec8f1b465030a066203f8a1" },
                { "fr", "fc4af11c3e845a475a2a650af3414417aacd2e3d4b7cd4939eacd77f496675894e57f63eff94bcce9c103c23cb6f50fb74ba012181f896ac178b783a468291aa" },
                { "fur", "a37944cf76665d884fed52d6d3c956375de08c5f466f2075e6a894e906a4869e3dcec81dd6309a382588e1217a504c8ce6a68eb6f9fb38df6050c60177f289e7" },
                { "fy-NL", "7be109376e127e2714f6f7a7301785d983b297c4c0b19de5d9b3288a0cded5514cfe203c803ba232b6db5d7a331c92f09f01dca04ffd6a6a0020f3c03048af9d" },
                { "ga-IE", "2e57cd79bf8bee027f162842bc5b961b09c30c3c71ac7252ff1a92203fe0f43a89d7e912d04eee80217623e52eec84088d677c10bd3fdd04f156b064b91768ee" },
                { "gd", "c5174be018671eb572eefb37b055672390140ac904d108eb7cf424aaf70e017ea1b946e21c72272cf4b8aaf4d3be50b42b073d976a6f923af18b45d49703c85d" },
                { "gl", "0fea67f8647cd250deab71851fc01ecab87a0a3d4dafb3988732e8a8c40b5f4d6a648015cd1fac57007e608df99ce8264dc566535df11931291d4717175e523a" },
                { "gn", "4e6c55b16d174cf1e28860c68087fa1a387194a780ded081d2f101ad5ee94993db71a2fa3a7953d629af57781e0ff2a2f4cdbe31864946880bc01860d15779e9" },
                { "gu-IN", "f6e446b17ce47fcbe6168d74fd95ba7868bddf91a72b224bd7bc75a3ff43b550c476c27ce7fac072703b494a3273ec26d93744a3b962c8cec75dcaed7429bd40" },
                { "he", "85dda0d8b1502a082a24dacf129967024ceffe63252b02d37c48bf75552ddab88840beebf0b4ed1cf05bd09cad0a75afef7eeb7b13512cec73072323ac9ce017" },
                { "hi-IN", "2ca2f150207b8a98e5d8ada14e164e70eb0c2587387924549f82805bac80b19f212812fe5f71d1749ada6c123d4113eb7756e78751a3e2091784acd8989ac376" },
                { "hr", "ef7778f94d6aa4760f9736c94ef7e3603a4befa7cef13b66a0a498cdb7f25f39cf79a36d0e686a5135319612a75922f381ec71ef95663c6c33886b7e5d1b6c37" },
                { "hsb", "b1a9fc9c9df811a2f46904a61266c359d0e58aa4b1adee1bfc214d114bff87bd3c5282ed5d1ca862f63fb8533545af05ef252bd9a48e7ac9a34a4c97d6059685" },
                { "hu", "97f695f501885b5072435d32f68b9dec2cae231871ab00c10a3e590b922b9875e7bcef4622e8f83ea51ee299a65f604ccdfc1aa244aba52612e2384ab0c10fac" },
                { "hy-AM", "157b2a317ac963fe2090f505f6f53305f0f143a643421c123d77a8fe6a3d3c8a3e0c2e11bf4d603cd3a2677bd0540a93ad7f6cdc2cdbf9c54d51ed03787279a0" },
                { "ia", "244e4d51fbc070e790e3b0aaa10b52e64ca51ef4d2f2b452160eb2391f5d3effcae2457ec2760a66b5876ea84f63cb4b7dcdcbf8590d4ba68e898cdafd303974" },
                { "id", "22c30e8fb0d8ea51a234a8e505191a10c5ba231c237f02f699e41985ab04644108c1994013ae7fe9b85068d67587d545b0f8da0cbeaa220668d127b45e7834da" },
                { "is", "c9ece21ec7e210a85b0aff4913ff9abff2ade8c106c1dae02696be325135d3f8ea6991d8741584df053bd93b97ac2cee53b14ccf91886e553fdd18df5017d572" },
                { "it", "e82d3eb696f14f6841a3874597e5b12dd509337ebf56b1192d52e8445b711240b26a1719d16e9ad5e79598d42c09c64bc8c42e8e7379ac6358a3955892ee845a" },
                { "ja", "4b848c1e61e3e2f2402749798a473f472e1ab31187ce1bcdc3381ac04a669590022049661029017538614523f086fcc0e024824fc2240a2a09ae09c0f857ce57" },
                { "ka", "83b78f1a2c8ee4b6cb0382b1f78ec585bc74f613ce6192a5d9a9e62b13ba04e00da606f487c9a25887e49ea36d4ea8c05367b863be21235f386a32762adc0111" },
                { "kab", "b1de0dcd522f5d65b47472301dfcf726b6352d28ff28e26a0734d6cd98f8bbf372f7095a70fd04653bfb4a06d84e264b283771bc61845f3551096a1308bb35a8" },
                { "kk", "888db2237925a0b54c4b0f266b9457770633b65afd6ccf7c45ff4b6494e371275a207b68b38b67d8d21fc4776352fa3db3ee8d3197086f3ca3ab6a2a60d9285d" },
                { "km", "36a478feae1296dc409e8f6892cc749b58db5a03ded07457cc8c2fcc74d844544a046ffb947f734c51066ed90dbb804969d8e7e7855d683cd6bdead9bde701e1" },
                { "kn", "ccad715ded9fe6e79080fc569aadd2ecdd2ec96661908747b126be3526d1d461c3fd7dc773cff16c004d48f25b94e0a88bd68af6a10d6b2cf14506414fb983d6" },
                { "ko", "5ac08298155f89dd823635d235a8a7d7409705be1810e9c85f1fcea9e9eaebd1516b7a8dd177ce56c6308df7a73563785fa4761d8f02480e2c78a312e6aa113a" },
                { "lij", "dd9805057c0566b65690bd67dd507600b5a804d77c5f5ad07e5b3d88885423c1b95c24b279ff067277196b2d26988e2eb08c296407ff8b554f798e3ea344574a" },
                { "lt", "e69512b2314e3ec54781397c85e640589f06a9db20be9654fbce3a97ef8e47d82902fef313098fb7150d5d0b975e5b6e53a70e32681225c212160dac604eab12" },
                { "lv", "e4bc39b2285b4ca58e334920826f5888e8fdb0f2946629bd498821d28921b931974a0a739bae512679531869e0f7694065217bac6211d9f06c46650ee45b9581" },
                { "mk", "2bd156c6752aab0a067461f850a463a3dfd357b929304e4b0c92387923872ff5016844646611b69828b637541762bb7b5d26978d760b9286cf08e7ba4f3b5bfa" },
                { "mr", "bd536374c1fbe017b6587f2bbb10c02e4b40c338ece4b679fbb820b8e8f7abe7e6838d1a8a46f0338e542d43376d530aa7fda30225e8ea8f807d2f301c9a0f08" },
                { "ms", "48eac4fbb8c12d5e66852447c2c418b889420db9045108b6885377866afaabd1ba50e6997cca7f8ab46a5ec2bee8f8d05481bf8e2a5b3af8deedb14d9cd5e650" },
                { "my", "96e394d848154ecf054acb928c5149a44120fceeba2ac83aefda0a78d531183bfe79319dacf23e0ed5059d63d9e5fd900d18fa64de26ab4d32b5fb08dbc7d6cd" },
                { "nb-NO", "300da1d8f83e8db264984f46f058b72c5e389d01452604d5b8ca8e9b8f41b42140f6ce9917099155fd9ee71bcdfdf9449473359d01b2c7810c1dc68c956d1a8a" },
                { "ne-NP", "55e45d62845392615024607095665476fcf91ed9ae954d7f448c6340321407d81ffbbcd31511d38937bec6afe819b3d62bb35b84d95db90b27358cf498836eba" },
                { "nl", "8c3b5084dfb67a9305b83a7e471cc01bed5bb0a469f1a079f0ceea44093a301847f3201e58d7c28cdbfde7ae94c5d4f91ff308f1ae905ce017e716e3d6d5e0c2" },
                { "nn-NO", "861dd30c0cb37c63cd8ed249fd3c2d2ff9609b9c3f16911fd7d99dafe6d0d604291c9856830337401b9374dfc8e1a04c00b78bc447aa6d3f105d91777ff3974b" },
                { "oc", "acbb8bb2b386a9e7f69eaa585c29381280db992c389b4b471d952d01ddd5180ac48e568118e5d495995509e7a6ad9b4122e7a2a23fab8300c552a85fea38f9f1" },
                { "pa-IN", "fa33298c119be354ce0cdaadc923e7b54576784497085d010dc8bc409164bbd48ae4fcaa8dc574ef9619f8e66f5e3ca6b3f63bbfa97885a02320baf4e7b8e733" },
                { "pl", "dcb4d41f826bfa4618f9f355a7e67d8f7ae3bf155ba2ae929fbfd091792d360f2c65fc963347469f560504fb64b064ad7213ca16dedf9c4aac0b3ad70dd01b55" },
                { "pt-BR", "c0e3688e00305a5967c8571ee620e02b199d83adc33c5a076f5d1511eec9cf190012ebabd9856579d87b354ea7063715b5a99c3fd4dbe4f9ee47013d4ad2fd4e" },
                { "pt-PT", "2075400ad519b242da1c92c43d30ca40a346468ee6d52e36562c9ef24519928ce298501df3bb4cd99fc078cc7d2535e7a280e42326b2a7e80b46dee926063e5c" },
                { "rm", "c737e9e2e9955ec3a55b9a136be74944a95bb021da9769e82373f497e943ef635434456d57c250743c6309030e265395141f86d7f140c06251dc2f7f9a085b56" },
                { "ro", "6dd919ffef753ea07f8c6ea5b3a8eccd04c1c1127857a8feb02804c88187c35f1090dd5b7d807c2ba22fd4d61b281389c2d219fce14fda5811e7763b8b5a93f8" },
                { "ru", "3fce3a8c5653c0bc7d34d1e9c9359612c3d2c279f13cc7eeaa649d365d83623cd05bd34c05b5c1c9a25130a1e3f50911a9a861cbc9d0b6465e63deed4f691e74" },
                { "sat", "278b271fbe02b5ff916fe55655620721834eb132bc6b4e4489d4067c37a900d5921a67c2b981a9df1ad3aec51a1bc70ce7cbf2c8999e08b9aa1dce1573fae0a6" },
                { "sc", "99919e12a7231b4dc3926b16e5f93a0c808ecbe828942844515f8a74b5d75fffc50848083d8a2edbb2f2b992b0f8a664b375af3a8d91931b92fe8571cdca8360" },
                { "sco", "7496c9cb797e76975e7fae6f3f342d8e59b6df0bae4b40e280663b602c90da3e0955682c1c60ca98fca579a4d494be7e5baa8128255fe06cf9ceb33e6ad8c5fb" },
                { "si", "e2093296b350701087e17bb9db0e698945a9f483a07ea99e79a26a611591be4da0e178630f9cc4042344babec77b8ff45adedd24c912a64d36403f7ebde7c9c9" },
                { "sk", "bcc404a7f3826c57108aa311c864925cf1abf5f9f8755cbb515ae3e0cf044edeed955ef96853a16c690e0955fc5c378296d2cbe69d2380792a06beda23882417" },
                { "skr", "aa574a769e22f21fbbeb099127354e49eacac8238e0e3d8f9e2c1a4e025a252d94f95b0fa7033badbf8901cfff5ce13d14394692c886549604413b25a68d356f" },
                { "sl", "9ffe948d3fce90ba88321478c6b04d6dd15b28862b2e535f62daaa64cad93022bfa072135a2e38f610e52319deaa8986e22d3930087e690b168aed2ccfeb25cc" },
                { "son", "a593c51e5b954306a6ac3ccd722f7055837dce2c7d68df2a7bf69ff52fefccf8788fb004b168c686f10b4a06fe4f6a9ddf6f348e24744b751c325d24b1229668" },
                { "sq", "cb1ac82890417fee4efb68e57b3045fd73a757e01c96b31481d83173661ee363f4e5f1f81504a49ab5748dd082f64b96922f84127fb2ae28337962043dfabded" },
                { "sr", "bb46c0ac2e344d67936ec3d912734e1152d67ad6784715b499755e838a3eb33bc6e522973eddb8b75b400d7205b35911c2e12d65cebc63b129bff9f29bd564e3" },
                { "sv-SE", "95fe55562efe0ddd7aeb239d7781fcb911b842c4d4413cf52ff833490e3ac1c1c4cbcf103dbe0a1edbd10c5b7390e86256f1cc2a5e9491ca50091b99295652a7" },
                { "szl", "689a1510f74514fa80efee81176853c9c430fc248feb3ec00b5aaa23aab21c51d847ccad47f7913b7c57baedb1aa93e38e92af2b918f4b793518872c2a873bf0" },
                { "ta", "3ca08ca2e325e8197316fafad4c949042ebe66ab6a1cb20c5bbe2dc237c68bbf0c5b0f6a57f5529e302d9eece5cad1e818ad4b1eb81750be3247259b7fe2e1e9" },
                { "te", "217e4a550b9b4d87832e2fd99192524ebe939d375c486c182a0f7ff70f21434a31fe2c59edf631d0ecb5ec3a962e183a4fd28561c4e90851721e015826bcd16e" },
                { "tg", "13ec44871c37492a89ec07178a8e7d59b9111216086d03c1a3a166bb3d78aa28663772f21400fa225735c673dea8a35c5cc445ecb4c10e594a447cf29d58df45" },
                { "th", "748f6b0d2bea36d0d54d459c3e728ef7b5b452206ce776f9c13c9a674740663aadb45e3e9834d138687bb70dd363372e20bc6f0bd8bf0344c712b77e631d3088" },
                { "tl", "f6dee665b7bd1930e7c409d20a2294487b532647c05c436676556ef0f6ddf37c8ab044faf797afd1a7318f535382ac5eaf9ea35cd7168de330b3d7f4cd2cb2b1" },
                { "tr", "cb1422e143bd2c8bc23007de51606f4882c21a8e50fa392b2a4bfef9e851456801e18d2fb6f10eecd72d14b5eb967eb562e9a61e7b071d76538a54974e9d36b1" },
                { "trs", "6a8dfd150a37398814d73caabd020b756fce4c968efee7eada115719abcdc9cc293db2bab4945aef8756cd3b4aef473204927b63d645390fc0e2db0e90e300c5" },
                { "uk", "261cd830e6087a013301b00ca4f4545e1a37a290f342ba8d183d54f4efa6c1a48b195139f75a5d428cad44a682d7bc8bd1f413c74a25be81ec5a54f5a60fad06" },
                { "ur", "d97be6a689d1a624af85e1d4089dd0a9092bff7f2c67eea3f2e6cc5126686255d8dbfae645770e783bba00aa92a584aa3ad9d422114bab4d23792bd11cbbacda" },
                { "uz", "94b24d754ab705b9ed64eccb53fe94531cf53c09da0980e01c7c31173bcfeb0a75a749dc257f79fd474d617fa89b7929c4ff240fedf56b919188187bb3d39677" },
                { "vi", "93bee86c94ec4c96b1c20a2b2993f52a1dbbe9f4737d46fcfb1592ad19792fb7f5b1f09da406d2bc46c56bf3f81ac6629f108109f7c1121ec12fbf0159812757" },
                { "xh", "f7b264c1fe736bb19adfb52b4453b099fffebb748d820b050468f01635bb5b7733c28f7848d6a31c2b4b9ca59d76990a50e5129b37116b9e11b1753265827b53" },
                { "zh-CN", "c59fabad36d6465cb8f816d79826e25e859697916e1bde331e26cde03df76f84a80bec4e61fe00105a5cc09dc3e7b39b01077629344b679d6b2e0262f7fbdab9" },
                { "zh-TW", "c0e1ee996b5dcd224d4c1f93793ea4c3ccd8f54e68dc689b9b2bf4e9cd64437a6704deca46800646e112e2c018169c3d03bb23b85be3859d9f0fd379a514d023" }
            };
        }


        /// <summary>
        /// Gets a dictionary with the known checksums for the installers (key: language, value: checksum).
        /// </summary>
        /// <returns>Returns a dictionary where keys are the language codes and values are the associated checksums.</returns>
        private static Dictionary<string, string> knownChecksums64Bit()
        {
            // These are the checksums for Windows 64-bit installers from
            // https://ftp.mozilla.org/pub/firefox/releases/157.0.1/SHA512SUMS
            return new Dictionary<string, string>(102)
            {
                { "ach", "47ce1e32e9098a35174d58be74715471d78635419a8feeda39a411b07f8c960c22221b7d394c9caf560700d278a638fdb77d19891995f0511a7ee21cb71eb2be" },
                { "af", "f38e8afbd97fa7724d5ec2629e08a16c83b9e7a5c07a1b2125f3b86373ab889ef2b0b60786425b4f638f7209730b1066f7e90e26c181f4699a01e4c126f97988" },
                { "an", "cafeb3aea3f3fa1c26c1de488225377a0bf4fee946713d422105c0e5e009cdfefc7c2ea8377580a346e6f54ae26243bcaa78411b927c784a7a0a4aa7968abb54" },
                { "ar", "cf2463d518499d41e03b0412ee2a9371b7ef5e9b4233186311ecfd48db6c0207d3bb94bf36336c3080e7878c0f97582c0e885d3ccce4b5d710dda76913f0e4a9" },
                { "ast", "c10f34a39ba9bf6ace39729aff1caa5262221fa7921e8ceb6f623efaa5701f27ddee92fc0641d575384bd97aa0252a89f547e1d287fdd0db6b61817b2b7ae9c5" },
                { "az", "1d9baea5fbd84a8f1a78ee70d95e4b22f449cb0afb152801f63e30e44f5e1f5d4ef29afe0563c20130a1a6f963ff390c8930540328b4433657c48a50589a7d7e" },
                { "be", "f0f6a932357c8117572087ad518dedd8566831879d410c540ee13b7de36eaf9d3a8e19a3c0da9436e8f5ba951c6122c1724cc12d966268cc00df6024174c9d36" },
                { "bg", "dfa63ecf11dd0a249108c2d092c0b328de618c3d9f90f416ee56c1497107ecca30d682361fe4ce69cefeebf7b3844ba8889d24578271f63c38f0a9664619f1a8" },
                { "bn", "6f4aa63e127523bb37402c3078e71328e706a246c7292e943bed1cf58a0d190b2eea04f8bbdbaf1406f3dfc6d1848152c5f4ef531084e4eb901e51ef048ce320" },
                { "br", "9b4f293dd566d8464a0b1c5b28eb03227ae058412af9fe651bacbd58ead1d9aa1a87c2d0ba62f3e3a38074f81b108f6942bd300a50fc08fb73bb733f86979005" },
                { "bs", "dc9ca9b5ce8a9179e84e09e8006d26589fd2938dee5287d034af496bcc0b2f3dba267caee1e05658df090aa0b830e96704f9c0243835fd5c716a0f5e04495372" },
                { "ca", "835559ea6f6af5af857df850c54ad9abed96ea4aaa3733e273b7b4198cc96dbd7d806e0b9755856114f067e54d67e0c71db6681a8191b153dcf301cb676764fa" },
                { "cak", "1f6fe4206734b7c8f796e9be5bd633b4099d6ef4841768eb013cf50b90c9567b3738c8625c99ae6ec27e7146775cc891187db658784d379165428b06eb6d5f15" },
                { "cs", "946c1f30d359196735d04b15d238d1245de84ff48501f45b83b57016435039d4d935e38f1433d2848e7c3b45d9d290d9b375585c422c16148d606dc25308e0c1" },
                { "cy", "bcd6a7eb3ce997e3ba56af3efeacfb2041ea31afbb4b819f7332ebbe43771763d8e99a0d2a351eb102f69b7efb84e49b44ea1ea9451efd942d583f48082b050c" },
                { "da", "ed5dfdfa9937c335b7d75b8124a458e27b2ca273ea1e6da74a225429ea595394efc9079921058c7fafe8326c9c3d269916bf0e2a5fb21d3ee45b8aa3781e5883" },
                { "de", "a342a428d2bc8e6e83e43cd3dcaaf792d788154349eb6503905c99068ef79322376f51e1ca192c4dede03af1db033afe699518686008649673a836f22c944d14" },
                { "dsb", "b181ec08de9f89230b0cc018674ec5967254917e3288a5b21284dc3f69dfa104fe291b8316687740d5cf5127b6f6badfbee0ac08dc0fc39215ad6751efc9f2a1" },
                { "el", "01edd3760cc0ca33ca65e17015363c9b864d0fd0dd90262803f2ba73ff338d6246091a46ea1c5623d99f53a4adeb82e33d0cb02ec8b79aed0018909a2f0a4db6" },
                { "en-CA", "35b17e72b69923eefd0924284c822ddd6a3dd225f6a502b6f134f7bc77654d133132bb1f8f33c58f0050ce810f76bee5f6e0d778d5eb5e083cd5f3d04ac212ce" },
                { "en-GB", "270273c58b9c9d0dfb14545297183819b832735f616e744a764a58e58a476b9ba22d48041957ce11ba243b7add6cd3ff4f1b79cc0efeee4e67f5e7c5214a0f4e" },
                { "en-US", "5e9cb7c6b8d00e2eb780350b03a4915f637dce4696205802535bad50b486cb8b4ee9afcfdcafd1b3bb75b31541c68db63a2e0da891c8b5b1248e3b681330ec57" },
                { "eo", "178013dc6901ad9a988f912e7a2a3d8de10f7455da21322332fb1ba8aa69d0fed0c3be763d9936df808c8b3363b5edabcc883fbe1ba6b2e4e26f9e58141bcfcb" },
                { "es-AR", "4fcfb350567e4057d236f37ad3a01f7c24236052cb1aba88c93d6e02b3960972c935a1ef8d234fb8453d280bdf669773e956968aa52b0a84a2cb780b900dce33" },
                { "es-CL", "dd6522f6acb6a197c3611be02e8e9c5401fc4e58ddee8d176fa03096dfbea656d749addbc40d924b2ab91a4d8f587ecdcaa082d7dc7c0e73558a521d2cb57390" },
                { "es-ES", "fa8f7f87185669fb7de5a323fae2f4f46911e1d6cb1616883b10221a2d460dfcf16b1431e1ec71068530b4a6bd5c5b1f81ea8811014cc2d296607b0e91eadf4b" },
                { "es-MX", "b69f5da8357d657e29c7ee86f6ff06dec225a73050ad17c3118e0286f30826b82c911ab6201dcebc27d35dc0fa26a70c0b75f92e7f74d6087e7b5148ed788009" },
                { "et", "ef126052645f1850ad036a11143172d62d9c74dbb464d91995b4e9ecdabe6f4d6ee3bcd9f3803828fdaba93c3845720771785d053fc6bcbfc67c3067070b6fa8" },
                { "eu", "4992b146bb8a77006c75b554da5e729fbe3270f5217316957cbcf7cac679eec7eb17b211353aa4f861e5e54955d72121cb36c52b2d10c542f23ff6085f86c8fe" },
                { "fa", "3af6ed3161ac4e6a8ef3757b5db552a5b1404e028d5194f4f60ea45772e2f202697e7861cb43a1da5ee546f899b1946a056314bbc0edf632a5dbc5582ef70f5c" },
                { "ff", "fc6302151f00df84a3e653189db707d8d9df4e35c6b46401b13356281cc72b5429f431b031679b34ce912ec501129a3554a704e1e1e0a77a620d683b3b2814a3" },
                { "fi", "a5da41fc0ba58d7801b0c95b30a22b038ac1fe7102771f5fa032f0f9bff99f6e360638a32a0bfbcf50c5992e11fca44d4e815c0a9ddd72de815f2164f3a6936d" },
                { "fr", "069de39deb7761bc64ae68323db71713b11321dab1c0d77d6f30188d4727a258b42fa8b4fbfb80bc211f6fb32847d125d63dbc5b4b17c2b2a6bb990b55386db6" },
                { "fur", "b010e6a4b1628b7977966aaed5b531ed415d2822796dc114fe822746e78c2b1c278484a3afeacdd5684aa4bbd69542b4fa6339025b8532942ee237e1b25a02a4" },
                { "fy-NL", "843da9dad5674701d225602ff1976ca67f11a211107526240763fabea1e1c77c56f2cfd7ac5b612cc63d42191668579aa4f8c272c06a35043f165ecd779210c0" },
                { "ga-IE", "0f1aaf444673f9d59392c4c003cd36bc22b62d14eb2a315af03132f68efc910be522872826b6f0b5bf6c30ac168a929d6a0f86e0594f7cc4f372afe6e17f1991" },
                { "gd", "ca9d93e7c6dc5e852a66ef2def44685e43726aaff18ea4aa90c81719668b1bab617bd1106d0494595ff24a35c43a2c56d72d909abce360ec8b1a73e6a0332a69" },
                { "gl", "d27de9b89bef20659671d3fb6b7528089c6037697bdad74e0af53a21181572457e33b5067b0442850d53bac378ffb19b9cc864e8ba1c8cad785a1542fe68de8c" },
                { "gn", "f8879974b435eb0ad5c20c54fc084239a0fa8359c0873e3a5acb6cb5a400d1b17ffbcd7f0dd0c48b6775d6b41230558b0f6f2c728bbcc3291ba281dbfa385351" },
                { "gu-IN", "d791223b7681dbda15fac87677b23853fb3bb6fdeaedad604fac02bac16409c8d2a7a1f5495a6371178ae4ace1faddf2c7670351ef17816fa514a9d09242e2ec" },
                { "he", "8ccc34bda66538d49586a3d2bdac6f014960a3cc97e92217d5c4533b3a39e61bb5c0e1dc345c4c5e7d550f33ac44fd3a016398f7cdab443410ea28fe15e0a868" },
                { "hi-IN", "e0482031db146603fdb3d0480be55c8694118829888723a33b40e5c7e02201b44b3dc0d1ccc0c41da1e3ad613d73429f3946689058c78cded584f8f9ef926f8c" },
                { "hr", "7b267c80de660063c9e5e766cc9b2cf9999c465748f8c5c0b172748cbdf2ae99e6a1b36ede39afa99e38bb38acd523c12c8819ecb4eb4d3d0d885f4c6a9fd467" },
                { "hsb", "d236cb5510ba8cac32ebd2b31302ce0cc52ebcc094d568e9fb54692e54a617a89eebec254fdd78395c582702192163aa8daa464c7b384055fe6c6ec4452430e1" },
                { "hu", "a7060a9d02159715e9c42d21bdbe585b9d1df629ca6b50ec173f192b8581083ea3aad42da28563baca85829145ca8df0e2eb08df0e42cd302cac8e9a6976f7c7" },
                { "hy-AM", "c72f70369a2167a201cc42548fc315a7b1c255d079c27930d1df7152057ad6836e8da33fb2b5097009560236f89433371487d2156b625ee615050b1f00bd36f4" },
                { "ia", "fde1f41e5c09a52ab2a0805b52c32817f48a0be2fe136b7e20fc778c514a7556c9a235588916d4dd731633c5a4ecf1033fadccbf700993c2e5747e3f3d9e9d7f" },
                { "id", "b792f5932ef826a2fa9ec3f0d5867ecb53f98ea170c1924705f56da2fea93cfffa1d7bbede158782561e52159616c1c52914a94ee9a253de2b48d8471552f5c5" },
                { "is", "6d74faf71c0939aed0648f05582637fe5956a9ef17f350c60ed58ab71b519b9399bc7ab85ddc3f4ab46e042550af9081626e41ff0c14360f5dd11ed7334f8c4e" },
                { "it", "edcd54a1539bbed9c980685278a3498542f5f30a69408481a50f283dde14c452e3c40486af1f29faa538a8eedf868402bc3fe3b51caffc4e63ba07d0189e38df" },
                { "ja", "5efb4426ebd8952fab42f56ac4e0a21de5033a68202839f54cd7a1cba789b8a8f3140b81afc7ee3621cacc6f23cbd02eeb7f8a5ed9f27913dd0a52ad3cfe57a8" },
                { "ka", "84bfe0ba6a7dd5ccdc295562c2ca6ce7a9190483ab899f7d3368a9c1f0bda497ddfc167ee4018821be14f3c50272c6c6a650c2295d554d0fc0663bb1978a0225" },
                { "kab", "a7f16ac71a00e94e37a8223053938f2a33f23177497b3d71ba9473abf63d7a40413b446b1ae26e08116ecd3c4553a0301abd7c6fc07db5464e80a15325bdf167" },
                { "kk", "790163a3c57f98c6e9a2014d52d5831f09eaf57846e6ab5aa6b732a7f0c52d70509264af9b1caefa68445e49a593d76655889a34a5f53c400d111b405d96ff82" },
                { "km", "52adc307461016ec801bef4544aee19a0d30a93a15a75ebcfc9ed0bb6ad3818dad3c223e00c66bc20518b6b6ee533e765bbcc1fe491bfd6a747967e484132c90" },
                { "kn", "9d1d6c2d6460fe820e6dba98c2ac32e2c6f1924905776044386e9b443d1a09e141079b1c314d1d21e2be194e351ba3384d9a95689b41bbfd43dc525bb1d508af" },
                { "ko", "b99c7c4846d47bef30425e71db3f331701886ba36fc4d2bf217b58fc467d692a581127a847b99afba340ce0425c0616df0a11cf930a44f1e76b14d65bb7ab319" },
                { "lij", "19ef761537e04ca9281f6dad4d05df44770591955776e0e5b6568b873972ec05493581ad99def62c1d3c214e16062dec46da7e9e888f7802c0523d64ad1a7216" },
                { "lt", "a9320b1db86d1916b8cc16ab63f47c64b52233291636f9293dd50295522bf606778baef1da3163f4e49be65fec6822877a66f824f55c1d890241076fca1a1d27" },
                { "lv", "c37b93c469b6c89c37bc64235a8961338c96e387521983943c9cd18574c738ed48ec2a25228b7e3e51d1f08edeac3e1bce1d2ac3f159d627bf25aeace6eb2e4b" },
                { "mk", "21123a6192ce31423623bfe3f1630009b1c2054209f3e442e9b911948f75e78ba274fbddadcf4200be310e8f9cbfcb5ed601b5a67b5b815ffb104c080dc1ee69" },
                { "mr", "89acd24aa75c9b1ab1fd2409bf81e45a6082794179caa59a002b748605ce8ca0c1e4b3bcd3432077453d36ebb8f52624818996a10001f935a17b5d4d6092d51d" },
                { "ms", "8c3171083db7e80473906b2096633bae3a2e5e4064e3ca083163541bdb2daa604925e54521ee3656dc781eb467977c5cb6db31866d56002ca3ed64787d9a9570" },
                { "my", "fbc3c67bedb5ab41f98dbd941717979bfd02551fa11a0b24657e587da564f672f958b37bd9f5c0e697208f20b5a21fffce661f7a3fd94006f56ec034c3807de1" },
                { "nb-NO", "e8779510ab563277209f7b6adffbfe1db39628dc85945229d0cbccf72c3d045b571e039d0e3906547d3cebee5e5abd8cc116a4156a59f77ed24d8df880cfa8af" },
                { "ne-NP", "3c857f18f4118c79ba0db287fb1e20af3e48641957958940576b306f36d3153ad976bc8c906f0f9ec58157dae07162af519e1b610756b4ead59c3273067d4bbe" },
                { "nl", "85dc8c1e086420d1808c6b7883be9c8813386d1a65b695c389833c65bb43321784a753874b85362239899391d8257a1f9a9ac470d0f45a7d8532bc5341cf513a" },
                { "nn-NO", "7ef50404d93dd06f12f0905049d1d7f01d12d9e59fad20cc80d1568c1b4771f53bdd27942b1ce4a035cb616571f1f37b239a5a619b6d1c89d546805e4cc4e2fc" },
                { "oc", "81f6ba6085d29ea1449758c2bfd9c9fb61ae083c91dd2174822eee9230332c7c4d5b4007ff2abd37179f6da47ad1bb6616ec077b82fa646e151196b202f3e787" },
                { "pa-IN", "335924322cf707f9c4b86ced4f25e15ca405c6be8231b2aa60fdca13bac41285d9204a684b4e19173e240c3a436fabf4a6ab9bfbab2ae9e632f15981f2ba2197" },
                { "pl", "4c59e727bd4371bb29cf1b4aa6225b6cc3017400a66d149ff83ef2b9321165953fdb2ac07e7e0cdc53557c009be6b37aa2ed5f25414c8599922be4e0812a0dc4" },
                { "pt-BR", "0268cad955a3cda27683eaa599c163f6d161d6c8564e78f8652c498de97d8ba42bf4234c4aee5632da7e3527324005323e18b48b0ec85aec205315e918943ca8" },
                { "pt-PT", "0589fe8ecc533f71bc9375cdaa78d7d1f9d03a5dcb0c347c9971b62d67361f23d567d464b6cf83443913932aa49519535afc955acdaf555673bfe54b0afbbe67" },
                { "rm", "d242b5360130500007fa679ac0ae603804514f1ded8ea45018461eeed3235b67a8572c79f38335b2036598e98aa2501c2ac86dfd54e5211acf45a2dc298682ec" },
                { "ro", "c2fd2c3659161a26a7e5e9c6ee98164a714bb9be855f105d302ca892af938f46d70b12b7924092305e74750a0fb8208f866cde2ffb91f3603449a050765ab25d" },
                { "ru", "57c7328ba92ca10c76f5bd2bb5fcc45fe4a3e907ea8c531b3b24969ea76123d7965eb743239efdaa6f7038c4629dcfbf5cb18b8e843f8b474b7b492a86786d3b" },
                { "sat", "f8b4ce6e471cb6424956d280f3bd2034c5c72e5f237909694a1c51c39779c2eb8fc1211a368f75efe50efba5b2a2cad94feeeaadf63f916ea62d3aa11d2a52ad" },
                { "sc", "caaf0c0702041fb4e8d53e9576ba073fa09bdd7b2ddff1e9d8d2a6f9394bce551b38ea91bee7e01655d93e86fb8588ea18e8b3bf15fa43e3d65595fac5e507d3" },
                { "sco", "0546863aab5af8b8401c9754c16b21205c1ae2a0ded7220bad68ad03c417219649502e642412501ee411a387e091c1d497a4584e2d3fedf259b3f2a9e9c1a7de" },
                { "si", "9e8562b89341a3b05f8e40e7bb32ccc434525f8ce1fbdd8a1f59cbe6c1561bf234f681952eb8db51894dc5dac17dd3fd934812ae79edda8ae9ba73787ba0d813" },
                { "sk", "3ccd455c4eb3f9da84e7e0012f4f55d02c88c8d95658252bc82c74428e7dd0047dfabacfe82135e3e68c948f8765d37a457c71527fcc694cc4c47baacd6d2d23" },
                { "skr", "b45df710c0ab7a1ea987c1fa1e03f4ea7fe9db81e26d94b93ab2531f2236dcec61f3a96017f9930a419116249068fd602b916269236a777abae8b9df96ae0828" },
                { "sl", "b495900fbeae77bcf8b3fc1c7167bc067130de17d87637f343881eea95e652c00a67c1c115717bb2ede72840ef3f1bdbd971ab0bf75c7978f76afd0c769eae2d" },
                { "son", "782b901251ce06caec8c79a9900823ee222119deb284d470920353cf1adea289bdb4025dc13344aabe9fd39df3cd8728fdc07de4c142e25ce5a7e67116359f72" },
                { "sq", "fc99c5514aa04a7a5899513148b4d489c28c83572bfa9090f5865547a4be11216db110af2e1e6f117972639fbccf5abe50115006fd909e781b98ca604acfaa5a" },
                { "sr", "bc64dfde731496bc8af62333409a6d27107ee0eacce9d05b3b7828e7b90ef640ef839bdc5e03dfab6a87752a6152ccece45603be8bd84f5ce12b3050be41ff17" },
                { "sv-SE", "71bf068299e055a3f0fba0d1618a2cbb7a4bf1becc0e63d65f0d924ba8ffca3d19cad2118ad8daf4c3b12f8d719d6290e13238ee33006bb55caa65e173cd1b99" },
                { "szl", "2a82ddb05bc863d95685408d8c270f740fbc4a6e097e9ead5f3f8ebbaf49488f0347d7eca4cc7a06f3868fbe8886fa36d38323d36591c1c5f7684c31f8795558" },
                { "ta", "d3cd1b1da708a127077e8dce3ea8f4ae134bb995e4a4275b1b1bfb831e712115f38e2509fc2b74a696b29f52f1eee280a1bd94c8012cadb5b78b50e45aaf0348" },
                { "te", "2c7bda643793d3ae14be4e5090a8afcdedfef14a86789e97f22db36941a88c63edf65e34bb4985b3906d2a797ed058db76c20e2feaae13d107a48fa09c58d4e5" },
                { "tg", "721e412a47119e541c738e5dca88c2d9e8f8a7f6757df4088aabb7e86d668d086e53361f2e2d840d54b65f30cf32a742e77071f0184a24f1adc30d6f35f7347c" },
                { "th", "e6ef3781f0ca428ca3afacf11cd4a22e6b7a400951a689d5af1671317faf8b02a5e671dabd443d4802bffbaf578460e968dcacd097ec8a8473294361a048f279" },
                { "tl", "78cc56353ae1ceb5425e2be20b16f57b1fe6e4387e2ff4d28b13fdc2450f5ce89b61d60251e3fa64544b260253546db955f4158bb9b052a5f68ac2876fbd9f2c" },
                { "tr", "d11a6cffa72b97a778be92d116c0b65c8bfecfe68d66847eff5fdccc033389c95b4cb5ab54beb2c5eb23f31ff25d452c1c55abebeb2fc9f47a972445380e91f6" },
                { "trs", "b838c3c90f91cd8f3c768815077f9c42ee5e5a7b6334e67bf6bc7ad8ab2a02bc23e935bd195883795fbf4b4b6bf4b0cc2fdde1e66abddcda1dddaad91eca4b7f" },
                { "uk", "355c600e29816f5e0a567424b048e132f17ba1d20945d2f40408f297002b9fed031adf8abc0a779aa6b29a8ff414887ef6b49871e5b436016cae7634af983a9e" },
                { "ur", "009a58585977725e5d2cd791c8e077ae28aa90aa4378117abad10e10ddeb123af9328e3e57b42ab55ba570b878b1303acb7ba4dff0926f15d9499ddea99d3f7a" },
                { "uz", "f0f016c6619aea01cb3b5e3e73c56f20f2b02e81c47420ef5648ae3772031025cac19e065c5ad4e427c9a7872a5b59ae5577ff084cb98edbd6e4ba506920d80b" },
                { "vi", "cf6cc151636e97caa10e8b061321763a5dc0b63d0bc9d56b7cee802b8c4b4c406eb9cf55f96668542503391b142b99c27b50e15e23c82993749d1df7ba5682a5" },
                { "xh", "2c6890ecc6b6bd561e625e3fd88ebade64f4facfbbd5b6a2b5d7268d239f15531d7759d3121b80623070457ff9dce9855c00a59f868949de9fddd4682ade0efa" },
                { "zh-CN", "861dfc3eba53c4d2a1a5a775b04d874e10f01f96ba91e65dc1c375210ae787171af3f2cbf60abc1ec7abe03e011c1f5f52de85be862405da3bc163c44a6f5fcd" },
                { "zh-TW", "dd2fb9b824ae147457d7aa5195c8a77a48cea740e3186d8fb3a6365b37d23c997630dc263943fcc231b58347334cc39dba63dff97b2dfb944df9bdbf01ee4fa8" }
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
            const string knownVersion = "157.0.1";
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
