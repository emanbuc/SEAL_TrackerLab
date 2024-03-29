﻿using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using FitnessTracker.Common.Models;
using FitnessTracker.Common.Utils;
using Microsoft.Research.SEAL;

namespace FitnessTrackerClient
{
    class Program
    {
        private static Encryptor _encryptor;
        private static Decryptor _decryptor;
        private static SEALContext _context;
        static async Task Main(string[] args)
        {
            Console.WriteLine("SEAL LAB");
            Console.WriteLine("Setting up encryption...\n");

            // Add Initialization code here
            _context = SEALUtils.GetContext();

            // Add keys code here
            var keys = await FitnessTrackerClient.GetKeys();

            // Create encryptor

            var publicKey = SEALUtils.BuildPublicKeyFromBase64String(keys.PublicKey, _context);
            _encryptor = new Encryptor(_context, publicKey);


            // Create decryptor
            var secretKey = SEALUtils.BuildSecretKeyFromBase64String(keys.SecretKey, _context);
            _decryptor = new Decryptor(_context, secretKey);


            while (true)
            {
                PrintMenu();
                var option = Convert.ToInt32(Console.ReadLine());

                switch (option)
                {
                    case 1:
                        await SendNewRun();
                      break;
                    case 2:
                        await GetMetrics();
                        break;
                }
            }
        }

        static async Task SendNewRun()
        {
            // Get distance from user
            Console.Write("Enter the new running distance (km): ");
            var newRunningDistance = Convert.ToInt32(Console.ReadLine());

            if (newRunningDistance < 0)
            {
                Console.WriteLine("Running distance must be greater than 0.");
                return;
            }

            // Encrypt distance
            // We will convert the Int value to Hexadecimal using the ToString("X") method
            var plaintext = new Plaintext($"{newRunningDistance.ToString("X")}");
            var ciphertextDistance = new Ciphertext();
            _encryptor.Encrypt(plaintext, ciphertextDistance);


            // Convert value to base64 string
            var base64Distance = SEALUtils.CiphertextToBase64String(ciphertextDistance);


            // Get time from user
            Console.Write("Enter the new running time (hours): ");
            var newRunningTime = Convert.ToInt32(Console.ReadLine());

            if (newRunningTime < 0)
            {
                Console.WriteLine("Running time must be greater than 0.");
                return;
            }

            // Encrypt time
            // We will convert the Int value to Hexadecimal using the ToString("X") method
            var plaintextTime = new Plaintext($"{newRunningTime.ToString("X")}");
            var ciphertextTime = new Ciphertext();
            _encryptor.Encrypt(plaintextTime, ciphertextTime);


            // Convert value to base64 string
            var base64Time = SEALUtils.CiphertextToBase64String(ciphertextTime);


            var metricsRequest = new RunItem
            {
                Distance = base64Distance,
                Time = base64Time
            };

            LogUtils.RunItemInfo("CLIENT", "SendNewRun", metricsRequest);

            // Send new run to api
            await FitnessTrackerClient.AddNewRunningDistance(metricsRequest);
        }

        private static async Task GetMetrics()
        {
            // Get encrypted metrics
            var metrics = await FitnessTrackerClient.GetMetrics();

            LogUtils.SummaryStatisticInfo("CLIENT", "GetMetrics", metrics);

            // Decrypt the data
            var ciphertextTotalRuns = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalRuns, _context);
            var plaintextTotalRuns = new Plaintext();
            _decryptor.Decrypt(ciphertextTotalRuns, plaintextTotalRuns);

            var ciphertextTotalDistance = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalDistance, _context);
            var plaintextTotalDistance = new Plaintext();
            _decryptor.Decrypt(ciphertextTotalDistance, plaintextTotalDistance);

            var ciphertextTotalHours = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalHours, _context);
            var plaintextTotalHours = new Plaintext();
            _decryptor.Decrypt(ciphertextTotalHours, plaintextTotalHours);


            // Print metrics in console
            PrintMetrics(plaintextTotalRuns.ToString(), plaintextTotalDistance.ToString(), plaintextTotalHours.ToString());

        }

        private static void PrintMetrics(string runs, string distance, string hours)
        {
            Console.WriteLine(string.Empty);
            Console.WriteLine("********* Metrics *********");
            Console.WriteLine($"Total runs: {int.Parse(runs, System.Globalization.NumberStyles.HexNumber)}");
            Console.WriteLine($"Total distance: {int.Parse(distance, System.Globalization.NumberStyles.HexNumber)}");
            Console.WriteLine($"Total hours: {int.Parse(hours, System.Globalization.NumberStyles.HexNumber)}");
            Console.WriteLine(string.Empty);
        }

        private static void PrintMetrics(SummaryItem summary)
        {
            Console.WriteLine(string.Empty);
            Console.WriteLine("********* Metrics *********");
            Console.WriteLine($"Total runs: {SEALUtils.Base64Decode(summary.TotalRuns)}");
            Console.WriteLine($"Total distance: {SEALUtils.Base64Decode(summary.TotalDistance)}");
            Console.WriteLine($"Total hours: {SEALUtils.Base64Decode(summary.TotalHours)}");
            Console.WriteLine(string.Empty);
        }

        private static void PrintMenu()
        {
            Console.WriteLine("********* Menu (enter the option number and press enter) *********");
            Console.WriteLine("1. Add running distance");
            Console.WriteLine("2. Get metrics");
            Console.Write("Option: ");
        }
    }
}
