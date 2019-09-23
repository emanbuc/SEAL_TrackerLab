using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using FitnessTracker.Common.Models;
using FitnessTracker.Common.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Routing;
using Microsoft.Research.SEAL;

namespace FitnessTrackerAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class MetricsController : ControllerBase
    {
        private List<string> _distances = new List<string>();
        private List<string> _times = new List<string>();

        private readonly SEALContext _sealContext;

        private readonly KeyGenerator _keyGenerator;
        private Evaluator _evaluator;
        private Encryptor _encryptor;


        public MetricsController()
        {
            // Initialize context
            // Getting context from Commons project
            _sealContext = SEALUtils.GetContext();


            // Initialize key generator and encryptor
            // Initialize key Generator that will be use to get the Public and Secret keys
            _keyGenerator = new KeyGenerator(_sealContext);
            // Initializing encryptor
            _encryptor = new Encryptor(_sealContext, _keyGenerator.PublicKey);

            // Initialize evaluator
            _evaluator = new Evaluator(_sealContext);
        }

        [HttpGet]
        [Route("keys")]
        public ActionResult<KeysModel> GetKeys()
        {
            Debug.WriteLine("[API]: GetKeys - return SEAL public and secret keys to client");
            return new KeysModel
            {
                PublicKey = SEALUtils.PublicKeyToBase64String(_keyGenerator.PublicKey),
                SecretKey = SEALUtils.SecretKeyToBase64String(_keyGenerator.SecretKey)
            };
        }

        [HttpPost]
        [Route("")]
        public ActionResult AddRunItem([FromBody] RunItem request)
        {
            // Add AddRunItem code
            LogUtils.RunItemInfo("API", "AddRunItem", request);
            LogUtils.RunItemInfo("API", "AddRunItem", request, true);
            //var distance = SEALUtils.Base64Decode(request.Distance);
            //var time = SEALUtils.Base64Decode(request.Time);

            _distances.Add(request.Distance);
            _times.Add(request.Time);
            return Ok();
        }

        [HttpGet]
        [Route("")]
        public ActionResult<SummaryItem> GetMetrics()
        {
            Ciphertext totalDistance = new Ciphertext();
            int zero = 0;
            Plaintext plainTextZero = new Plaintext($"{zero.ToString("X")}");
            _encryptor.Encrypt(plainTextZero, totalDistance);

            

            foreach (var dString in _distances)
            {
                var cipherString = SEALUtils.BuildCiphertextFromBase64String(dString, _sealContext);
                _evaluator.Add(totalDistance, cipherString, totalDistance);
            }

            Ciphertext totalHours = new Ciphertext();
            _encryptor.Encrypt(plainTextZero, totalHours);

            foreach (var timeString in _times)
            {
                var cipherTimeString = SEALUtils.BuildCiphertextFromBase64String(timeString, _sealContext);
                _evaluator.Add(totalHours, cipherTimeString, totalHours);
            }

            Ciphertext totalRuns = new Ciphertext();
            Plaintext plainTextTotalRuns = new Plaintext($"{_distances.Count.ToString("X")}");
            _encryptor.Encrypt(plainTextTotalRuns, totalRuns);


            var summaryItem = new SummaryItem
            {
                TotalRuns = SEALUtils.CiphertextToBase64String(totalRuns),
                TotalDistance = SEALUtils.CiphertextToBase64String(totalDistance),
                TotalHours = SEALUtils.CiphertextToBase64String(totalHours)
            };

            LogUtils.SummaryStatisticInfo("API", "GetMetrics", summaryItem);
            LogUtils.SummaryStatisticInfo("API", "GetMetrics", summaryItem, true);

            return summaryItem;
        }
    }
}